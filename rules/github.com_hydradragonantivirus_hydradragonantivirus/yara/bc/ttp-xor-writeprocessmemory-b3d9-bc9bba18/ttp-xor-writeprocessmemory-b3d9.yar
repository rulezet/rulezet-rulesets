rule TTP_XOR_WriteProcessMemory_b3d9 {
  strings:
    $key_b3d9 = { e4 ab [2] d6 89 [2] d0 bc [2] fe bc [2] c1 a0 }

  condition:
    any of them
}