rule TTP_XOR_WriteProcessMemory_1b89 {
  strings:
    $key_1b89 = { 4c fb [2] 7e d9 [2] 78 ec [2] 56 ec [2] 69 f0 }

  condition:
    any of them
}