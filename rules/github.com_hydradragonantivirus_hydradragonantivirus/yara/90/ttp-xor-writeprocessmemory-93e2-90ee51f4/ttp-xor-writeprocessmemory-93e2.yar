rule TTP_XOR_WriteProcessMemory_93e2 {
  strings:
    $key_93e2 = { c4 90 [2] f6 b2 [2] f0 87 [2] de 87 [2] e1 9b }

  condition:
    any of them
}