rule TTP_XOR_WriteProcessMemory_69c1 {
  strings:
    $key_69c1 = { 3e b3 [2] 0c 91 [2] 0a a4 [2] 24 a4 [2] 1b b8 }

  condition:
    any of them
}