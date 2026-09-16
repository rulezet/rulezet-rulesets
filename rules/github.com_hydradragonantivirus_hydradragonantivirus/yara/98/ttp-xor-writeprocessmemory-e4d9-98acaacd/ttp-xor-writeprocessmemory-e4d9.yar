rule TTP_XOR_WriteProcessMemory_e4d9 {
  strings:
    $key_e4d9 = { b3 ab [2] 81 89 [2] 87 bc [2] a9 bc [2] 96 a0 }

  condition:
    any of them
}