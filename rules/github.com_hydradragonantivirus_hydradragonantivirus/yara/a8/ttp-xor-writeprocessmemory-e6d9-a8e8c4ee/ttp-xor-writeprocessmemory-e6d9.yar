rule TTP_XOR_WriteProcessMemory_e6d9 {
  strings:
    $key_e6d9 = { b1 ab [2] 83 89 [2] 85 bc [2] ab bc [2] 94 a0 }

  condition:
    any of them
}