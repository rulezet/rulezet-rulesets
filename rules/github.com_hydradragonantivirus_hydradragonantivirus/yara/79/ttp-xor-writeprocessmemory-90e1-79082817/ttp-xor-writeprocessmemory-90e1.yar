rule TTP_XOR_WriteProcessMemory_90e1 {
  strings:
    $key_90e1 = { c7 93 [2] f5 b1 [2] f3 84 [2] dd 84 [2] e2 98 }

  condition:
    any of them
}