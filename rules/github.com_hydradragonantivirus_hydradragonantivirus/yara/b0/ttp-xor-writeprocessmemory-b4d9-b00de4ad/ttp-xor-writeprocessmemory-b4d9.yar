rule TTP_XOR_WriteProcessMemory_b4d9 {
  strings:
    $key_b4d9 = { e3 ab [2] d1 89 [2] d7 bc [2] f9 bc [2] c6 a0 }

  condition:
    any of them
}