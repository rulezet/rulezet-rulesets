rule TTP_XOR_WriteProcessMemory_2b89 {
  strings:
    $key_2b89 = { 7c fb [2] 4e d9 [2] 48 ec [2] 66 ec [2] 59 f0 }

  condition:
    any of them
}