rule TTP_XOR_WriteProcessMemory_ed90 {
  strings:
    $key_ed90 = { ba e2 [2] 88 c0 [2] 8e f5 [2] a0 f5 [2] 9f e9 }

  condition:
    any of them
}