rule TTP_XOR_WriteProcessMemory_69c6 {
  strings:
    $key_69c6 = { 3e b4 [2] 0c 96 [2] 0a a3 [2] 24 a3 [2] 1b bf }

  condition:
    any of them
}