rule TTP_XOR_WriteProcessMemory_03b0 {
  strings:
    $key_03b0 = { 54 c2 [2] 66 e0 [2] 60 d5 [2] 4e d5 [2] 71 c9 }

  condition:
    any of them
}