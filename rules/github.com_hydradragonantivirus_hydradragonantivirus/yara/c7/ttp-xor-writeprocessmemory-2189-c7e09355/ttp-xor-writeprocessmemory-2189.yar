rule TTP_XOR_WriteProcessMemory_2189 {
  strings:
    $key_2189 = { 76 fb [2] 44 d9 [2] 42 ec [2] 6c ec [2] 53 f0 }

  condition:
    any of them
}