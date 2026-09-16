rule TTP_XOR_WriteProcessMemory_85f9 {
  strings:
    $key_85f9 = { d2 8b [2] e0 a9 [2] e6 9c [2] c8 9c [2] f7 80 }

  condition:
    any of them
}