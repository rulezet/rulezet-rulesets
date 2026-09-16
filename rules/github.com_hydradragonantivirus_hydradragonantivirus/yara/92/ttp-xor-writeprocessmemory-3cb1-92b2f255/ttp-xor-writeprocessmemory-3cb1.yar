rule TTP_XOR_WriteProcessMemory_3cb1 {
  strings:
    $key_3cb1 = { 6b c3 [2] 59 e1 [2] 5f d4 [2] 71 d4 [2] 4e c8 }

  condition:
    any of them
}