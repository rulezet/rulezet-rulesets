rule TTP_XOR_WriteProcessMemory_b089 {
  strings:
    $key_b089 = { e7 fb [2] d5 d9 [2] d3 ec [2] fd ec [2] c2 f0 }

  condition:
    any of them
}