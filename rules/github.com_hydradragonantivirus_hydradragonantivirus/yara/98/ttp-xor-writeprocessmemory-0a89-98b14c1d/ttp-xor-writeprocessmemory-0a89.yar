rule TTP_XOR_WriteProcessMemory_0a89 {
  strings:
    $key_0a89 = { 5d fb [2] 6f d9 [2] 69 ec [2] 47 ec [2] 78 f0 }

  condition:
    any of them
}