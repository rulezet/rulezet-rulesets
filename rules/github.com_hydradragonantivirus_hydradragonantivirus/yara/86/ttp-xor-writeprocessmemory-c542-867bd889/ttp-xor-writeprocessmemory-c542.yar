rule TTP_XOR_WriteProcessMemory_c542 {
  strings:
    $key_c542 = { 92 30 [2] a0 12 [2] a6 27 [2] 88 27 [2] b7 3b }

  condition:
    any of them
}