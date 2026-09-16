rule TTP_XOR_WriteProcessMemory_4289 {
  strings:
    $key_4289 = { 15 fb [2] 27 d9 [2] 21 ec [2] 0f ec [2] 30 f0 }

  condition:
    any of them
}