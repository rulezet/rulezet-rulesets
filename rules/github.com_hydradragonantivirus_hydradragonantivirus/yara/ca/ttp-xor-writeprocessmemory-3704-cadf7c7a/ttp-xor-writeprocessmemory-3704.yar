rule TTP_XOR_WriteProcessMemory_3704 {
  strings:
    $key_3704 = { 60 76 [2] 52 54 [2] 54 61 [2] 7a 61 [2] 45 7d }

  condition:
    any of them
}