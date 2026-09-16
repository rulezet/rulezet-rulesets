rule TTP_XOR_WriteProcessMemory_78a3 {
  strings:
    $key_78a3 = { 2f d1 [2] 1d f3 [2] 1b c6 [2] 35 c6 [2] 0a da }

  condition:
    any of them
}