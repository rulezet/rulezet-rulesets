rule TTP_XOR_WriteProcessMemory_8584 {
  strings:
    $key_8584 = { d2 f6 [2] e0 d4 [2] e6 e1 [2] c8 e1 [2] f7 fd }

  condition:
    any of them
}