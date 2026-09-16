rule TTP_XOR_WriteProcessMemory_85a8 {
  strings:
    $key_85a8 = { d2 da [2] e0 f8 [2] e6 cd [2] c8 cd [2] f7 d1 }

  condition:
    any of them
}