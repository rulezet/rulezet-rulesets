rule TTP_XOR_WriteProcessMemory_8889 {
  strings:
    $key_8889 = { df fb [2] ed d9 [2] eb ec [2] c5 ec [2] fa f0 }

  condition:
    any of them
}