rule TTP_XOR_WriteProcessMemory_b389 {
  strings:
    $key_b389 = { e4 fb [2] d6 d9 [2] d0 ec [2] fe ec [2] c1 f0 }

  condition:
    any of them
}