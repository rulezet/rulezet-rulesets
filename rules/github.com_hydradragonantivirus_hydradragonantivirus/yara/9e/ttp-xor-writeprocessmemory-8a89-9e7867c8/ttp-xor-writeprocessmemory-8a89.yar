rule TTP_XOR_WriteProcessMemory_8a89 {
  strings:
    $key_8a89 = { dd fb [2] ef d9 [2] e9 ec [2] c7 ec [2] f8 f0 }

  condition:
    any of them
}