rule TTP_XOR_WriteProcessMemory_1cb0 {
  strings:
    $key_1cb0 = { 4b c2 [2] 79 e0 [2] 7f d5 [2] 51 d5 [2] 6e c9 }

  condition:
    any of them
}