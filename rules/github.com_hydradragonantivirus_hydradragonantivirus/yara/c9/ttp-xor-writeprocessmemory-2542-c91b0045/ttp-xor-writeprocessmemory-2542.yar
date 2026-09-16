rule TTP_XOR_WriteProcessMemory_2542 {
  strings:
    $key_2542 = { 72 30 [2] 40 12 [2] 46 27 [2] 68 27 [2] 57 3b }

  condition:
    any of them
}