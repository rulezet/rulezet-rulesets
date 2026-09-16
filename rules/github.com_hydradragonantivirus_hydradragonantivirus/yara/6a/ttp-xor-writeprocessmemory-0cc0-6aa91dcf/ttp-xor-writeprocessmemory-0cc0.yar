rule TTP_XOR_WriteProcessMemory_0cc0 {
  strings:
    $key_0cc0 = { 5b b2 [2] 69 90 [2] 6f a5 [2] 41 a5 [2] 7e b9 }

  condition:
    any of them
}