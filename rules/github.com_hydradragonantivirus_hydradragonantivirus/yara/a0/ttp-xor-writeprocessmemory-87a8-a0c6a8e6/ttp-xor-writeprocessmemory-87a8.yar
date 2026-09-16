rule TTP_XOR_WriteProcessMemory_87a8 {
  strings:
    $key_87a8 = { d0 da [2] e2 f8 [2] e4 cd [2] ca cd [2] f5 d1 }

  condition:
    any of them
}