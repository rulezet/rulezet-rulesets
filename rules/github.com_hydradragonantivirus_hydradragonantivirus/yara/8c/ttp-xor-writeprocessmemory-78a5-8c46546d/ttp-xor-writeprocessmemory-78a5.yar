rule TTP_XOR_WriteProcessMemory_78a5 {
  strings:
    $key_78a5 = { 2f d7 [2] 1d f5 [2] 1b c0 [2] 35 c0 [2] 0a dc }

  condition:
    any of them
}