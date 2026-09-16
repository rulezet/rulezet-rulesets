rule TTP_XOR_WriteProcessMemory_59c0 {
  strings:
    $key_59c0 = { 0e b2 [2] 3c 90 [2] 3a a5 [2] 14 a5 [2] 2b b9 }

  condition:
    any of them
}