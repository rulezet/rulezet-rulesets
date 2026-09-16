rule TTP_XOR_WriteProcessMemory_3cc0 {
  strings:
    $key_3cc0 = { 6b b2 [2] 59 90 [2] 5f a5 [2] 71 a5 [2] 4e b9 }

  condition:
    any of them
}