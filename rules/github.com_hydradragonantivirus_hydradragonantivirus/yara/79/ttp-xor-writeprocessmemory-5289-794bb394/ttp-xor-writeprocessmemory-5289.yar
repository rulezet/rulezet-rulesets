rule TTP_XOR_WriteProcessMemory_5289 {
  strings:
    $key_5289 = { 05 fb [2] 37 d9 [2] 31 ec [2] 1f ec [2] 20 f0 }

  condition:
    any of them
}