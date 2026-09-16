rule TTP_XOR_WriteProcessMemory_93f3 {
  strings:
    $key_93f3 = { c4 81 [2] f6 a3 [2] f0 96 [2] de 96 [2] e1 8a }

  condition:
    any of them
}