rule TTP_XOR_WriteProcessMemory_e0e1 {
  strings:
    $key_e0e1 = { b7 93 [2] 85 b1 [2] 83 84 [2] ad 84 [2] 92 98 }

  condition:
    any of them
}