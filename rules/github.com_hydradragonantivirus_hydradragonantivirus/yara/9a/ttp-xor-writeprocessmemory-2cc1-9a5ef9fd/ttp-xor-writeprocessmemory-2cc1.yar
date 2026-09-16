rule TTP_XOR_WriteProcessMemory_2cc1 {
  strings:
    $key_2cc1 = { 7b b3 [2] 49 91 [2] 4f a4 [2] 61 a4 [2] 5e b8 }

  condition:
    any of them
}