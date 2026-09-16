rule TTP_XOR_WriteProcessMemory_7ab0 {
  strings:
    $key_7ab0 = { 2d c2 [2] 1f e0 [2] 19 d5 [2] 37 d5 [2] 08 c9 }

  condition:
    any of them
}