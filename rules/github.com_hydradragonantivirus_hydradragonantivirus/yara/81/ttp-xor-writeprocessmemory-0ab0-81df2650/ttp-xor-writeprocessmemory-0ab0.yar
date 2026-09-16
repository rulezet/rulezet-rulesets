rule TTP_XOR_WriteProcessMemory_0ab0 {
  strings:
    $key_0ab0 = { 5d c2 [2] 6f e0 [2] 69 d5 [2] 47 d5 [2] 78 c9 }

  condition:
    any of them
}