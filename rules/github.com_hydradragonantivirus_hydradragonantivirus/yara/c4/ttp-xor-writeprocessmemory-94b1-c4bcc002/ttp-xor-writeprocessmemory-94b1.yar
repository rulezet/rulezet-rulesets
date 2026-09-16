rule TTP_XOR_WriteProcessMemory_94b1 {
  strings:
    $key_94b1 = { c3 c3 [2] f1 e1 [2] f7 d4 [2] d9 d4 [2] e6 c8 }

  condition:
    any of them
}