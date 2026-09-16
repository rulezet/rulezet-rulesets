rule TTP_XOR_WriteProcessMemory_bee2 {
  strings:
    $key_bee2 = { e9 90 [2] db b2 [2] dd 87 [2] f3 87 [2] cc 9b }

  condition:
    any of them
}