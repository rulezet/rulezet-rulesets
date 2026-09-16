rule TTP_XOR_WriteProcessMemory_54b0 {
  strings:
    $key_54b0 = { 03 c2 [2] 31 e0 [2] 37 d5 [2] 19 d5 [2] 26 c9 }

  condition:
    any of them
}