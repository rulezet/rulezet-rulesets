rule TTP_XOR_WriteProcessMemory_7489 {
  strings:
    $key_7489 = { 23 fb [2] 11 d9 [2] 17 ec [2] 39 ec [2] 06 f0 }

  condition:
    any of them
}