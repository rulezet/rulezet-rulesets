rule TTP_XOR_WriteProcessMemory_1898 {
  strings:
    $key_1898 = { 4f ea [2] 7d c8 [2] 7b fd [2] 55 fd [2] 6a e1 }

  condition:
    any of them
}