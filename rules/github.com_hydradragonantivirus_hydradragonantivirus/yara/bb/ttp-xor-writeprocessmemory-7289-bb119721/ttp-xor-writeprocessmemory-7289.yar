rule TTP_XOR_WriteProcessMemory_7289 {
  strings:
    $key_7289 = { 25 fb [2] 17 d9 [2] 11 ec [2] 3f ec [2] 00 f0 }

  condition:
    any of them
}