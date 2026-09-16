rule TTP_XOR_WriteProcessMemory_85d0 {
  strings:
    $key_85d0 = { d2 a2 [2] e0 80 [2] e6 b5 [2] c8 b5 [2] f7 a9 }

  condition:
    any of them
}