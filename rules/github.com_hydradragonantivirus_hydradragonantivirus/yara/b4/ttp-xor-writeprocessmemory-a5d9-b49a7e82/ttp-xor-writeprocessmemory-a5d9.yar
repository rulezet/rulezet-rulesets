rule TTP_XOR_WriteProcessMemory_a5d9 {
  strings:
    $key_a5d9 = { f2 ab [2] c0 89 [2] c6 bc [2] e8 bc [2] d7 a0 }

  condition:
    any of them
}