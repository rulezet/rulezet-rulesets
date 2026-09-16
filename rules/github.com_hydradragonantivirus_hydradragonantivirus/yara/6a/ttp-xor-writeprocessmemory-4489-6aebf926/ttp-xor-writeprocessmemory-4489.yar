rule TTP_XOR_WriteProcessMemory_4489 {
  strings:
    $key_4489 = { 13 fb [2] 21 d9 [2] 27 ec [2] 09 ec [2] 36 f0 }

  condition:
    any of them
}