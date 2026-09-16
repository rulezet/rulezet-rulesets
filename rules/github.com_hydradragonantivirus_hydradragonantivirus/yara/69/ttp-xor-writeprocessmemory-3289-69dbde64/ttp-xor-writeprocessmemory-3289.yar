rule TTP_XOR_WriteProcessMemory_3289 {
  strings:
    $key_3289 = { 65 fb [2] 57 d9 [2] 51 ec [2] 7f ec [2] 40 f0 }

  condition:
    any of them
}