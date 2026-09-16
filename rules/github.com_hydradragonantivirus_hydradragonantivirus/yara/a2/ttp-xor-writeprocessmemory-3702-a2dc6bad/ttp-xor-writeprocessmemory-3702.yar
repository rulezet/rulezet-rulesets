rule TTP_XOR_WriteProcessMemory_3702 {
  strings:
    $key_3702 = { 60 70 [2] 52 52 [2] 54 67 [2] 7a 67 [2] 45 7b }

  condition:
    any of them
}