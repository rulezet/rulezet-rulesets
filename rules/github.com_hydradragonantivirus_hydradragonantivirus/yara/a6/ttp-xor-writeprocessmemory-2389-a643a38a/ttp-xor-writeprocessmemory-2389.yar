rule TTP_XOR_WriteProcessMemory_2389 {
  strings:
    $key_2389 = { 74 fb [2] 46 d9 [2] 40 ec [2] 6e ec [2] 51 f0 }

  condition:
    any of them
}