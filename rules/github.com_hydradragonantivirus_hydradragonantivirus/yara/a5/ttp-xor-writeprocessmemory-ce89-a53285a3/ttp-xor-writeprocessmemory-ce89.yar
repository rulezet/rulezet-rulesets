rule TTP_XOR_WriteProcessMemory_ce89 {
  strings:
    $key_ce89 = { 99 fb [2] ab d9 [2] ad ec [2] 83 ec [2] bc f0 }

  condition:
    any of them
}