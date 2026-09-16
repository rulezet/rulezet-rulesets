rule TTP_XOR_WriteProcessMemory_4ab1 {
  strings:
    $key_4ab1 = { 1d c3 [2] 2f e1 [2] 29 d4 [2] 07 d4 [2] 38 c8 }

  condition:
    any of them
}