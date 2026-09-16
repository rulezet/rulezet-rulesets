rule TTP_XOR_WriteProcessMemory_5cc1 {
  strings:
    $key_5cc1 = { 0b b3 [2] 39 91 [2] 3f a4 [2] 11 a4 [2] 2e b8 }

  condition:
    any of them
}