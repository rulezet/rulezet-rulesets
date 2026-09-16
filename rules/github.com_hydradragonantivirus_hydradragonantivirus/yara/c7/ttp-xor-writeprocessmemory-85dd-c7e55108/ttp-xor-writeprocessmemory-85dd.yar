rule TTP_XOR_WriteProcessMemory_85dd {
  strings:
    $key_85dd = { d2 af [2] e0 8d [2] e6 b8 [2] c8 b8 [2] f7 a4 }

  condition:
    any of them
}