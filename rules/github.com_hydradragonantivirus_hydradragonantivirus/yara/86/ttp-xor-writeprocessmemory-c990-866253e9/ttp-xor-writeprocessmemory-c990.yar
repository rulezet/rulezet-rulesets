rule TTP_XOR_WriteProcessMemory_c990 {
  strings:
    $key_c990 = { 9e e2 [2] ac c0 [2] aa f5 [2] 84 f5 [2] bb e9 }

  condition:
    any of them
}