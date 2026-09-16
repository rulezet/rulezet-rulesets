rule TTP_XOR_WriteProcessMemory_35b1 {
  strings:
    $key_35b1 = { 62 c3 [2] 50 e1 [2] 56 d4 [2] 78 d4 [2] 47 c8 }

  condition:
    any of them
}