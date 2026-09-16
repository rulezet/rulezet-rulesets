rule TTP_XOR_WriteProcessMemory_73b2 {
  strings:
    $key_73b2 = { 24 c0 [2] 16 e2 [2] 10 d7 [2] 3e d7 [2] 01 cb }

  condition:
    any of them
}