rule TTP_XOR_WriteProcessMemory_69c0 {
  strings:
    $key_69c0 = { 3e b2 [2] 0c 90 [2] 0a a5 [2] 24 a5 [2] 1b b9 }

  condition:
    any of them
}