rule TTP_XOR_WriteProcessMemory_e0d1 {
  strings:
    $key_e0d1 = { b7 a3 [2] 85 81 [2] 83 b4 [2] ad b4 [2] 92 a8 }

  condition:
    any of them
}