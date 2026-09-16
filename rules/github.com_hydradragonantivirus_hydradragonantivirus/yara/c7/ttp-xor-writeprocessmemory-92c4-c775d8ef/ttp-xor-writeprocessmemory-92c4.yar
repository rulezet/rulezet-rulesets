rule TTP_XOR_WriteProcessMemory_92c4 {
  strings:
    $key_92c4 = { c5 b6 [2] f7 94 [2] f1 a1 [2] df a1 [2] e0 bd }

  condition:
    any of them
}