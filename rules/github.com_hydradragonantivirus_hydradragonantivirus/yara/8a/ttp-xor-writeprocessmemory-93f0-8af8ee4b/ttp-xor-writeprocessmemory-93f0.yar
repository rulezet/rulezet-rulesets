rule TTP_XOR_WriteProcessMemory_93f0 {
  strings:
    $key_93f0 = { c4 82 [2] f6 a0 [2] f0 95 [2] de 95 [2] e1 89 }

  condition:
    any of them
}