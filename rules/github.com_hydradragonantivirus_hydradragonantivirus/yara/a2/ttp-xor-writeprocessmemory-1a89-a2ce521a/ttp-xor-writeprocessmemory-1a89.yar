rule TTP_XOR_WriteProcessMemory_1a89 {
  strings:
    $key_1a89 = { 4d fb [2] 7f d9 [2] 79 ec [2] 57 ec [2] 68 f0 }

  condition:
    any of them
}