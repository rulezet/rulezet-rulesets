rule TTP_XOR_WriteProcessMemory_3ab1 {
  strings:
    $key_3ab1 = { 6d c3 [2] 5f e1 [2] 59 d4 [2] 77 d4 [2] 48 c8 }

  condition:
    any of them
}