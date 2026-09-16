rule TTP_XOR_WriteProcessMemory_45b0 {
  strings:
    $key_45b0 = { 12 c2 [2] 20 e0 [2] 26 d5 [2] 08 d5 [2] 37 c9 }

  condition:
    any of them
}