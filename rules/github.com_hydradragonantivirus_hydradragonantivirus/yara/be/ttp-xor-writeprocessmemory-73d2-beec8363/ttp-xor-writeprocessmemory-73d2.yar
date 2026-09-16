rule TTP_XOR_WriteProcessMemory_73d2 {
  strings:
    $key_73d2 = { 24 a0 [2] 16 82 [2] 10 b7 [2] 3e b7 [2] 01 ab }

  condition:
    any of them
}