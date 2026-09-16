rule TTP_XOR_WriteProcessMemory_7ab1 {
  strings:
    $key_7ab1 = { 2d c3 [2] 1f e1 [2] 19 d4 [2] 37 d4 [2] 08 c8 }

  condition:
    any of them
}