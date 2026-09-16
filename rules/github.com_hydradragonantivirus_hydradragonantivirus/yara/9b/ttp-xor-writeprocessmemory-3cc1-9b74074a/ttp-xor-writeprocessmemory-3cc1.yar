rule TTP_XOR_WriteProcessMemory_3cc1 {
  strings:
    $key_3cc1 = { 6b b3 [2] 59 91 [2] 5f a4 [2] 71 a4 [2] 4e b8 }

  condition:
    any of them
}