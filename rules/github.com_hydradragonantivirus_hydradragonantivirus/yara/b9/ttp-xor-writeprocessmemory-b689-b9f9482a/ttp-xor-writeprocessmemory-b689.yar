rule TTP_XOR_WriteProcessMemory_b689 {
  strings:
    $key_b689 = { e1 fb [2] d3 d9 [2] d5 ec [2] fb ec [2] c4 f0 }

  condition:
    any of them
}