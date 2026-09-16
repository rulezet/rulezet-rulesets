rule TTP_XOR_WriteProcessMemory_49a9 {
  strings:
    $key_49a9 = { 1e db [2] 2c f9 [2] 2a cc [2] 04 cc [2] 3b d0 }

  condition:
    any of them
}