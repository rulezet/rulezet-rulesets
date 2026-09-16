rule TTP_XOR_WriteProcessMemory_7cc1 {
  strings:
    $key_7cc1 = { 2b b3 [2] 19 91 [2] 1f a4 [2] 31 a4 [2] 0e b8 }

  condition:
    any of them
}