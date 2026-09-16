rule TTP_XOR_WriteProcessMemory_85c8 {
  strings:
    $key_85c8 = { d2 ba [2] e0 98 [2] e6 ad [2] c8 ad [2] f7 b1 }

  condition:
    any of them
}