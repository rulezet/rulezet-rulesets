rule TTP_XOR_WriteProcessMemory_52b1 {
  strings:
    $key_52b1 = { 05 c3 [2] 37 e1 [2] 31 d4 [2] 1f d4 [2] 20 c8 }

  condition:
    any of them
}