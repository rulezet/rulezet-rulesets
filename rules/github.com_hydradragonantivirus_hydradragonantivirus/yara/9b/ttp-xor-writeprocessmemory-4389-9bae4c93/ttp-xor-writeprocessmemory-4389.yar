rule TTP_XOR_WriteProcessMemory_4389 {
  strings:
    $key_4389 = { 14 fb [2] 26 d9 [2] 20 ec [2] 0e ec [2] 31 f0 }

  condition:
    any of them
}