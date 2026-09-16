rule TTP_XOR_WriteProcessMemory_e684 {
  strings:
    $key_e684 = { b1 f6 [2] 83 d4 [2] 85 e1 [2] ab e1 [2] 94 fd }

  condition:
    any of them
}