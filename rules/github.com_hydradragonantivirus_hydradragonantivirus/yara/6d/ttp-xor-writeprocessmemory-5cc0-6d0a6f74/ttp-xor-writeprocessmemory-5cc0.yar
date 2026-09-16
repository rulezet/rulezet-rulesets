rule TTP_XOR_WriteProcessMemory_5cc0 {
  strings:
    $key_5cc0 = { 0b b2 [2] 39 90 [2] 3f a5 [2] 11 a5 [2] 2e b9 }

  condition:
    any of them
}