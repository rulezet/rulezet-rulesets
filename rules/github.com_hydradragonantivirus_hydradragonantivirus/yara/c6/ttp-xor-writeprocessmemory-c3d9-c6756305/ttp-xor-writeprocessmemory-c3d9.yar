rule TTP_XOR_WriteProcessMemory_c3d9 {
  strings:
    $key_c3d9 = { 94 ab [2] a6 89 [2] a0 bc [2] 8e bc [2] b1 a0 }

  condition:
    any of them
}