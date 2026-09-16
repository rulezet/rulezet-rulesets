rule TTP_XOR_WriteProcessMemory_bb50 {
  strings:
    $key_bb50 = { ec 22 [2] de 00 [2] d8 35 [2] f6 35 [2] c9 29 }

  condition:
    any of them
}