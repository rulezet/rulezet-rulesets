rule TTP_XOR_WriteProcessMemory_92f6 {
  strings:
    $key_92f6 = { c5 84 [2] f7 a6 [2] f1 93 [2] df 93 [2] e0 8f }

  condition:
    any of them
}