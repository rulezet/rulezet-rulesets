rule TTP_XOR_WriteProcessMemory_3732 {
  strings:
    $key_3732 = { 60 40 [2] 52 62 [2] 54 57 [2] 7a 57 [2] 45 4b }

  condition:
    any of them
}