rule TTP_XOR_WriteProcessMemory_d2d9 {
  strings:
    $key_d2d9 = { 85 ab [2] b7 89 [2] b1 bc [2] 9f bc [2] a0 a0 }

  condition:
    any of them
}