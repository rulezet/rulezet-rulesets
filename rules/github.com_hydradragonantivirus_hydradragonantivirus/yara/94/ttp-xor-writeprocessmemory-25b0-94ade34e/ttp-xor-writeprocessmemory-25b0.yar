rule TTP_XOR_WriteProcessMemory_25b0 {
  strings:
    $key_25b0 = { 72 c2 [2] 40 e0 [2] 46 d5 [2] 68 d5 [2] 57 c9 }

  condition:
    any of them
}