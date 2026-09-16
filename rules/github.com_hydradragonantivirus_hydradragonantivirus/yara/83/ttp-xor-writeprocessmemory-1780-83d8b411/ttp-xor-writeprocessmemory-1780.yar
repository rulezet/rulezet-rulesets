rule TTP_XOR_WriteProcessMemory_1780 {
  strings:
    $key_1780 = { 40 f2 [2] 72 d0 [2] 74 e5 [2] 5a e5 [2] 65 f9 }

  condition:
    any of them
}