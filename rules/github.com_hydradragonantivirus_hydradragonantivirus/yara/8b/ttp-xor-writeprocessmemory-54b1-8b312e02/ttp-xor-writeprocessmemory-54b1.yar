rule TTP_XOR_WriteProcessMemory_54b1 {
  strings:
    $key_54b1 = { 03 c3 [2] 31 e1 [2] 37 d4 [2] 19 d4 [2] 26 c8 }

  condition:
    any of them
}