rule TTP_XOR_WriteProcessMemory_7442 {
  strings:
    $key_7442 = { 23 30 [2] 11 12 [2] 17 27 [2] 39 27 [2] 06 3b }

  condition:
    any of them
}