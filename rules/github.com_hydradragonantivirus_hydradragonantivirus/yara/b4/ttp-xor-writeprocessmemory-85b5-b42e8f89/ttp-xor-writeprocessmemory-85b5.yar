rule TTP_XOR_WriteProcessMemory_85b5 {
  strings:
    $key_85b5 = { d2 c7 [2] e0 e5 [2] e6 d0 [2] c8 d0 [2] f7 cc }

  condition:
    any of them
}