rule TTP_XOR_WriteProcessMemory_2dd4 {
  strings:
    $key_2dd4 = { 7a a6 [2] 48 84 [2] 4e b1 [2] 60 b1 [2] 5f ad }

  condition:
    any of them
}