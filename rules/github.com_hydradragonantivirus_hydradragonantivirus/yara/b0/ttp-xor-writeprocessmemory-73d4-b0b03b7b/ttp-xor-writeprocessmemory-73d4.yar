rule TTP_XOR_WriteProcessMemory_73d4 {
  strings:
    $key_73d4 = { 24 a6 [2] 16 84 [2] 10 b1 [2] 3e b1 [2] 01 ad }

  condition:
    any of them
}