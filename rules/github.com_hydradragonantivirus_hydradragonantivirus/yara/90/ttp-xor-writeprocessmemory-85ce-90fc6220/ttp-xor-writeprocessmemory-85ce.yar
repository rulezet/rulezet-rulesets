rule TTP_XOR_WriteProcessMemory_85ce {
  strings:
    $key_85ce = { d2 bc [2] e0 9e [2] e6 ab [2] c8 ab [2] f7 b7 }

  condition:
    any of them
}