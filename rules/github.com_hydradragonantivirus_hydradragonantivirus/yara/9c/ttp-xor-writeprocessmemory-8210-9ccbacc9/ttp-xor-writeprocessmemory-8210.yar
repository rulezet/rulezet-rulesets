rule TTP_XOR_WriteProcessMemory_8210 {
  strings:
    $key_8210 = { d5 62 [2] e7 40 [2] e1 75 [2] cf 75 [2] f0 69 }

  condition:
    any of them
}