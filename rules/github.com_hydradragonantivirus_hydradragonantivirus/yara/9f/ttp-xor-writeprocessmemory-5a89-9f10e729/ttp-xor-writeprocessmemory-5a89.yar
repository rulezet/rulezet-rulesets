rule TTP_XOR_WriteProcessMemory_5a89 {
  strings:
    $key_5a89 = { 0d fb [2] 3f d9 [2] 39 ec [2] 17 ec [2] 28 f0 }

  condition:
    any of them
}