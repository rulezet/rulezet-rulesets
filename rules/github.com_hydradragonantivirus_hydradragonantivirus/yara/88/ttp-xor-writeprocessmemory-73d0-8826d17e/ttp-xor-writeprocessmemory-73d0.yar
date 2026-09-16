rule TTP_XOR_WriteProcessMemory_73d0 {
  strings:
    $key_73d0 = { 24 a2 [2] 16 80 [2] 10 b5 [2] 3e b5 [2] 01 a9 }

  condition:
    any of them
}