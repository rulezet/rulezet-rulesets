rule TTP_XOR_WriteProcessMemory_62b1 {
  strings:
    $key_62b1 = { 35 c3 [2] 07 e1 [2] 01 d4 [2] 2f d4 [2] 10 c8 }

  condition:
    any of them
}