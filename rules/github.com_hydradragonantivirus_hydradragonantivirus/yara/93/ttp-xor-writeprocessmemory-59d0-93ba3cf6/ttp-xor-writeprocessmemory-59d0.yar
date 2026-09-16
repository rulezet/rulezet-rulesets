rule TTP_XOR_WriteProcessMemory_59d0 {
  strings:
    $key_59d0 = { 0e a2 [2] 3c 80 [2] 3a b5 [2] 14 b5 [2] 2b a9 }

  condition:
    any of them
}