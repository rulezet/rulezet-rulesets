rule TTP_XOR_WriteProcessMemory_93e7 {
  strings:
    $key_93e7 = { c4 95 [2] f6 b7 [2] f0 82 [2] de 82 [2] e1 9e }

  condition:
    any of them
}