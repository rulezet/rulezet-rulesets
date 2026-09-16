rule TTP_XOR_WriteProcessMemory_b2d9 {
  strings:
    $key_b2d9 = { e5 ab [2] d7 89 [2] d1 bc [2] ff bc [2] c0 a0 }

  condition:
    any of them
}