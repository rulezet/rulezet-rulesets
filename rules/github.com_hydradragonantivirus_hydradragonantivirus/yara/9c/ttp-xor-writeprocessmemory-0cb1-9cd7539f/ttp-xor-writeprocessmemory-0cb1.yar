rule TTP_XOR_WriteProcessMemory_0cb1 {
  strings:
    $key_0cb1 = { 5b c3 [2] 69 e1 [2] 6f d4 [2] 41 d4 [2] 7e c8 }

  condition:
    any of them
}