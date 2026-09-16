rule TTP_XOR_WriteProcessMemory_03b1 {
  strings:
    $key_03b1 = { 54 c3 [2] 66 e1 [2] 60 d4 [2] 4e d4 [2] 71 c8 }

  condition:
    any of them
}