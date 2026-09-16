rule TTP_XOR_WriteProcessMemory_73e2 {
  strings:
    $key_73e2 = { 24 90 [2] 16 b2 [2] 10 87 [2] 3e 87 [2] 01 9b }

  condition:
    any of them
}