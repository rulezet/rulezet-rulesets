rule TTP_XOR_WriteProcessMemory_92c5 {
  strings:
    $key_92c5 = { c5 b7 [2] f7 95 [2] f1 a0 [2] df a0 [2] e0 bc }

  condition:
    any of them
}