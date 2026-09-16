rule TTP_XOR_WriteProcessMemory_69c3 {
  strings:
    $key_69c3 = { 3e b1 [2] 0c 93 [2] 0a a6 [2] 24 a6 [2] 1b ba }

  condition:
    any of them
}