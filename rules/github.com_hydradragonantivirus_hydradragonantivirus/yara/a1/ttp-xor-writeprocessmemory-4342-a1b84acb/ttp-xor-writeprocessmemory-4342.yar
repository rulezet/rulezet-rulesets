rule TTP_XOR_WriteProcessMemory_4342 {
  strings:
    $key_4342 = { 14 30 [2] 26 12 [2] 20 27 [2] 0e 27 [2] 31 3b }

  condition:
    any of them
}