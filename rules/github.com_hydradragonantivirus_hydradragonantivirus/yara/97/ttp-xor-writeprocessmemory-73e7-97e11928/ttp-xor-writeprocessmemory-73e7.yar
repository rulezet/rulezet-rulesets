rule TTP_XOR_WriteProcessMemory_73e7 {
  strings:
    $key_73e7 = { 24 95 [2] 16 b7 [2] 10 82 [2] 3e 82 [2] 01 9e }

  condition:
    any of them
}