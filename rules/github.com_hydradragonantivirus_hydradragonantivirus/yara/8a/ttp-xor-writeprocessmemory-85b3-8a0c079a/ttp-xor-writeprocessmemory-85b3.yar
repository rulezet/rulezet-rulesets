rule TTP_XOR_WriteProcessMemory_85b3 {
  strings:
    $key_85b3 = { d2 c1 [2] e0 e3 [2] e6 d6 [2] c8 d6 [2] f7 ca }

  condition:
    any of them
}