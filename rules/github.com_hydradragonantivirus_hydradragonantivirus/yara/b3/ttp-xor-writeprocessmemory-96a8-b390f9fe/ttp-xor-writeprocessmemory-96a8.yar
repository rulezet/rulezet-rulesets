rule TTP_XOR_WriteProcessMemory_96a8 {
  strings:
    $key_96a8 = { c1 da [2] f3 f8 [2] f5 cd [2] db cd [2] e4 d1 }

  condition:
    any of them
}