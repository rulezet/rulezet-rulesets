rule TTP_XOR_WriteProcessMemory_4589 {
  strings:
    $key_4589 = { 12 fb [2] 20 d9 [2] 26 ec [2] 08 ec [2] 37 f0 }

  condition:
    any of them
}