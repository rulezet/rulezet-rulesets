rule TTP_XOR_WriteProcessMemory_ed96 {
  strings:
    $key_ed96 = { ba e4 [2] 88 c6 [2] 8e f3 [2] a0 f3 [2] 9f ef }

  condition:
    any of them
}