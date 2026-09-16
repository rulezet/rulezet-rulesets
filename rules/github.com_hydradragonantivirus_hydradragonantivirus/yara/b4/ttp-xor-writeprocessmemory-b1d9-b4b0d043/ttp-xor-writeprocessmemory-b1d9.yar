rule TTP_XOR_WriteProcessMemory_b1d9 {
  strings:
    $key_b1d9 = { e6 ab [2] d4 89 [2] d2 bc [2] fc bc [2] c3 a0 }

  condition:
    any of them
}