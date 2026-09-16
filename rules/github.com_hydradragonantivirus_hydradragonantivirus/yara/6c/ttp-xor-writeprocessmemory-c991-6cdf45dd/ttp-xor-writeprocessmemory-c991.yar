rule TTP_XOR_WriteProcessMemory_c991 {
  strings:
    $key_c991 = { 9e e3 [2] ac c1 [2] aa f4 [2] 84 f4 [2] bb e8 }

  condition:
    any of them
}