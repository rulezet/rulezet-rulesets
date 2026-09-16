rule TTP_XOR_WriteProcessMemory_a3d9 {
  strings:
    $key_a3d9 = { f4 ab [2] c6 89 [2] c0 bc [2] ee bc [2] d1 a0 }

  condition:
    any of them
}