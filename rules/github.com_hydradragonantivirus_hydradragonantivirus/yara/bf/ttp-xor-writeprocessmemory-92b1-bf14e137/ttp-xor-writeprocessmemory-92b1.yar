rule TTP_XOR_WriteProcessMemory_92b1 {
  strings:
    $key_92b1 = { c5 c3 [2] f7 e1 [2] f1 d4 [2] df d4 [2] e0 c8 }

  condition:
    any of them
}