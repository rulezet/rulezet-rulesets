rule TTP_XOR_WriteProcessMemory_ed56 {
  strings:
    $key_ed56 = { ba 24 [2] 88 06 [2] 8e 33 [2] a0 33 [2] 9f 2f }

  condition:
    any of them
}