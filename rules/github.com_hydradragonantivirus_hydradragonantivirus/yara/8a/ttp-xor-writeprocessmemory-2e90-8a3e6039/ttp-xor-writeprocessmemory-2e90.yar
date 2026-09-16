rule TTP_XOR_WriteProcessMemory_2e90 {
  strings:
    $key_2e90 = { 79 e2 [2] 4b c0 [2] 4d f5 [2] 63 f5 [2] 5c e9 }

  condition:
    any of them
}