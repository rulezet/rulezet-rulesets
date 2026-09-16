rule TTP_XOR_WriteProcessMemory_2789 {
  strings:
    $key_2789 = { 70 fb [2] 42 d9 [2] 44 ec [2] 6a ec [2] 55 f0 }

  condition:
    any of them
}