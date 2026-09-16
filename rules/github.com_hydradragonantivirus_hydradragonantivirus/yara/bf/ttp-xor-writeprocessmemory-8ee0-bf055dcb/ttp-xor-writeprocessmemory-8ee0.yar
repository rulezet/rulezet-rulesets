rule TTP_XOR_WriteProcessMemory_8ee0 {
  strings:
    $key_8ee0 = { d9 92 [2] eb b0 [2] ed 85 [2] c3 85 [2] fc 99 }

  condition:
    any of them
}