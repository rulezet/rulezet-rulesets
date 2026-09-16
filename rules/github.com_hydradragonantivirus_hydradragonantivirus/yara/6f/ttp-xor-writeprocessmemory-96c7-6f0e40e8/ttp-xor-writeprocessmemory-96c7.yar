rule TTP_XOR_WriteProcessMemory_96c7 {
  strings:
    $key_96c7 = { c1 b5 [2] f3 97 [2] f5 a2 [2] db a2 [2] e4 be }

  condition:
    any of them
}