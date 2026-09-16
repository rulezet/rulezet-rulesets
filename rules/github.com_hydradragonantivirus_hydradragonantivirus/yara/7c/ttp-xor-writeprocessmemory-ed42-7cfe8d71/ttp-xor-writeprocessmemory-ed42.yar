rule TTP_XOR_WriteProcessMemory_ed42 {
  strings:
    $key_ed42 = { ba 30 [2] 88 12 [2] 8e 27 [2] a0 27 [2] 9f 3b }

  condition:
    any of them
}