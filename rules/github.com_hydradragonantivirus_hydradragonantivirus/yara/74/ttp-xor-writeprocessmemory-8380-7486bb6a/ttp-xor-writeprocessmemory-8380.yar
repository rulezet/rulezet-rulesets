rule TTP_XOR_WriteProcessMemory_8380 {
  strings:
    $key_8380 = { d4 f2 [2] e6 d0 [2] e0 e5 [2] ce e5 [2] f1 f9 }

  condition:
    any of them
}