rule TTP_XOR_WriteProcessMemory_a389 {
  strings:
    $key_a389 = { f4 fb [2] c6 d9 [2] c0 ec [2] ee ec [2] d1 f0 }

  condition:
    any of them
}