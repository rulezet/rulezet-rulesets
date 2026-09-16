rule TTP_XOR_WriteProcessMemory_ed93 {
  strings:
    $key_ed93 = { ba e1 [2] 88 c3 [2] 8e f6 [2] a0 f6 [2] 9f ea }

  condition:
    any of them
}