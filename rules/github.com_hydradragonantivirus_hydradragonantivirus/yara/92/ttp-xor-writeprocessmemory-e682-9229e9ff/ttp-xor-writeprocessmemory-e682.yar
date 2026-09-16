rule TTP_XOR_WriteProcessMemory_e682 {
  strings:
    $key_e682 = { b1 f0 [2] 83 d2 [2] 85 e7 [2] ab e7 [2] 94 fb }

  condition:
    any of them
}