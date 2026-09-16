rule TTP_XOR_WriteProcessMemory_6b89 {
  strings:
    $key_6b89 = { 3c fb [2] 0e d9 [2] 08 ec [2] 26 ec [2] 19 f0 }

  condition:
    any of them
}