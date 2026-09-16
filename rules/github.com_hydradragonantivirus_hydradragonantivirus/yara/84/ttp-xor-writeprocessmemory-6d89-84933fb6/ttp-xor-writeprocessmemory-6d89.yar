rule TTP_XOR_WriteProcessMemory_6d89 {
  strings:
    $key_6d89 = { 3a fb [2] 08 d9 [2] 0e ec [2] 20 ec [2] 1f f0 }

  condition:
    any of them
}