rule TTP_XOR_WriteProcessMemory_5689 {
  strings:
    $key_5689 = { 01 fb [2] 33 d9 [2] 35 ec [2] 1b ec [2] 24 f0 }

  condition:
    any of them
}