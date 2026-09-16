rule TTP_XOR_WriteProcessMemory_4689 {
  strings:
    $key_4689 = { 11 fb [2] 23 d9 [2] 25 ec [2] 0b ec [2] 34 f0 }

  condition:
    any of them
}