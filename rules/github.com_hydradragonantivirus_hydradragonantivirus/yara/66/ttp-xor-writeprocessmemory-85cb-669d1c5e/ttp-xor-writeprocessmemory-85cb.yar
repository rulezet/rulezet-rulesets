rule TTP_XOR_WriteProcessMemory_85cb {
  strings:
    $key_85cb = { d2 b9 [2] e0 9b [2] e6 ae [2] c8 ae [2] f7 b2 }

  condition:
    any of them
}