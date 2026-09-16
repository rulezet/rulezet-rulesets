rule TTP_XOR_WriteProcessMemory_8180 {
  strings:
    $key_8180 = { d6 f2 [2] e4 d0 [2] e2 e5 [2] cc e5 [2] f3 f9 }

  condition:
    any of them
}