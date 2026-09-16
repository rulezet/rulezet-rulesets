rule TTP_XOR_WriteProcessMemory_92b0 {
  strings:
    $key_92b0 = { c5 c2 [2] f7 e0 [2] f1 d5 [2] df d5 [2] e0 c9 }

  condition:
    any of them
}