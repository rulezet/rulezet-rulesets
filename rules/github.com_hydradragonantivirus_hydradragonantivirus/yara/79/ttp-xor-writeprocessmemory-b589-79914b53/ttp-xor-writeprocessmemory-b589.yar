rule TTP_XOR_WriteProcessMemory_b589 {
  strings:
    $key_b589 = { e2 fb [2] d0 d9 [2] d6 ec [2] f8 ec [2] c7 f0 }

  condition:
    any of them
}