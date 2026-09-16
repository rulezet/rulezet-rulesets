rule TTP_XOR_WriteProcessMemory_b8a8 {
  strings:
    $key_b8a8 = { ef da [2] dd f8 [2] db cd [2] f5 cd [2] ca d1 }

  condition:
    any of them
}