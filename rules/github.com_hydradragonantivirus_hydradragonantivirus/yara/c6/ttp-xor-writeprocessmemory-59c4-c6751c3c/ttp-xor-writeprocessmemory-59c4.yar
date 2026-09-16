rule TTP_XOR_WriteProcessMemory_59c4 {
  strings:
    $key_59c4 = { 0e b6 [2] 3c 94 [2] 3a a1 [2] 14 a1 [2] 2b bd }

  condition:
    any of them
}