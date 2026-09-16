rule TTP_XOR_WriteProcessMemory_f789 {
  strings:
    $key_f789 = { a0 fb [2] 92 d9 [2] 94 ec [2] ba ec [2] 85 f0 }

  condition:
    any of them
}