rule TTP_XOR_WriteProcessMemory_1989 {
  strings:
    $key_1989 = { 4e fb [2] 7c d9 [2] 7a ec [2] 54 ec [2] 6b f0 }

  condition:
    any of them
}