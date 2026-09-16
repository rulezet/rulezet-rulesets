rule TTP_XOR_WriteProcessMemory_b789 {
  strings:
    $key_b789 = { e0 fb [2] d2 d9 [2] d4 ec [2] fa ec [2] c5 f0 }

  condition:
    any of them
}