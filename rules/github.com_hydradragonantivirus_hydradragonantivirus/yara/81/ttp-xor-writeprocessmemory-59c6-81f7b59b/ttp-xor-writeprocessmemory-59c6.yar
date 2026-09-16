rule TTP_XOR_WriteProcessMemory_59c6 {
  strings:
    $key_59c6 = { 0e b4 [2] 3c 96 [2] 3a a3 [2] 14 a3 [2] 2b bf }

  condition:
    any of them
}