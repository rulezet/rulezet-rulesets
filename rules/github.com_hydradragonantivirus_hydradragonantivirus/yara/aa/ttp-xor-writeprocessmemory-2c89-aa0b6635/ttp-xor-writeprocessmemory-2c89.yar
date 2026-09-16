rule TTP_XOR_WriteProcessMemory_2c89 {
  strings:
    $key_2c89 = { 7b fb [2] 49 d9 [2] 4f ec [2] 61 ec [2] 5e f0 }

  condition:
    any of them
}