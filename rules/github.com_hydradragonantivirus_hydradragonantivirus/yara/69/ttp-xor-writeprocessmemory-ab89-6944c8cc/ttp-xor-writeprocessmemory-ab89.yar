rule TTP_XOR_WriteProcessMemory_ab89 {
  strings:
    $key_ab89 = { fc fb [2] ce d9 [2] c8 ec [2] e6 ec [2] d9 f0 }

  condition:
    any of them
}