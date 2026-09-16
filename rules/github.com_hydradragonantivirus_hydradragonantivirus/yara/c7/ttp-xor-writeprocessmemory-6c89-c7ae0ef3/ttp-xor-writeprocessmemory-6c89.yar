rule TTP_XOR_WriteProcessMemory_6c89 {
  strings:
    $key_6c89 = { 3b fb [2] 09 d9 [2] 0f ec [2] 21 ec [2] 1e f0 }

  condition:
    any of them
}