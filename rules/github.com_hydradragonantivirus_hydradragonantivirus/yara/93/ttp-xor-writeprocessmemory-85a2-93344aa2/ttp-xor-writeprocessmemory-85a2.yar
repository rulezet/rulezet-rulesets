rule TTP_XOR_WriteProcessMemory_85a2 {
  strings:
    $key_85a2 = { d2 d0 [2] e0 f2 [2] e6 c7 [2] c8 c7 [2] f7 db }

  condition:
    any of them
}