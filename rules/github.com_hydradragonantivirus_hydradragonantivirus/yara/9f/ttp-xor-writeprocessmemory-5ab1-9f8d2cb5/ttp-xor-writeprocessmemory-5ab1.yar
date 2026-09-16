rule TTP_XOR_WriteProcessMemory_5ab1 {
  strings:
    $key_5ab1 = { 0d c3 [2] 3f e1 [2] 39 d4 [2] 17 d4 [2] 28 c8 }

  condition:
    any of them
}