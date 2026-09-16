rule TTP_XOR_WriteProcessMemory_1689 {
  strings:
    $key_1689 = { 41 fb [2] 73 d9 [2] 75 ec [2] 5b ec [2] 64 f0 }

  condition:
    any of them
}