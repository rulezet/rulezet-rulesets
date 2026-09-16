rule TTP_XOR_WriteProcessMemory_e0d9 {
  strings:
    $key_e0d9 = { b7 ab [2] 85 89 [2] 83 bc [2] ad bc [2] 92 a0 }

  condition:
    any of them
}