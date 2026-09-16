rule TTP_XOR_WriteProcessMemory_0cb0 {
  strings:
    $key_0cb0 = { 5b c2 [2] 69 e0 [2] 6f d5 [2] 41 d5 [2] 7e c9 }

  condition:
    any of them
}