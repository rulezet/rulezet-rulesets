rule TTP_XOR_WriteProcessMemory_73d6 {
  strings:
    $key_73d6 = { 24 a4 [2] 16 86 [2] 10 b3 [2] 3e b3 [2] 01 af }

  condition:
    any of them
}