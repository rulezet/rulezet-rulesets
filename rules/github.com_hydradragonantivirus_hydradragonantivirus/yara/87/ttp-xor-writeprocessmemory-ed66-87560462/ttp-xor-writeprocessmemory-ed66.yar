rule TTP_XOR_WriteProcessMemory_ed66 {
  strings:
    $key_ed66 = { ba 14 [2] 88 36 [2] 8e 03 [2] a0 03 [2] 9f 1f }

  condition:
    any of them
}