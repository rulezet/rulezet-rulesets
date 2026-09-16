rule TTP_XOR_WriteProcessMemory_8291 {
  strings:
    $key_8291 = { d5 e3 [2] e7 c1 [2] e1 f4 [2] cf f4 [2] f0 e8 }

  condition:
    any of them
}