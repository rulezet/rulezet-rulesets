rule TTP_XOR_WriteProcessMemory_6dd1 {
  strings:
    $key_6dd1 = { 3a a3 [2] 08 81 [2] 0e b4 [2] 20 b4 [2] 1f a8 }

  condition:
    any of them
}