rule TTP_XOR_WriteProcessMemory_0ab1 {
  strings:
    $key_0ab1 = { 5d c3 [2] 6f e1 [2] 69 d4 [2] 47 d4 [2] 78 c8 }

  condition:
    any of them
}