rule TTP_XOR_WriteProcessMemory_79c0 {
  strings:
    $key_79c0 = { 2e b2 [2] 1c 90 [2] 1a a5 [2] 34 a5 [2] 0b b9 }

  condition:
    any of them
}