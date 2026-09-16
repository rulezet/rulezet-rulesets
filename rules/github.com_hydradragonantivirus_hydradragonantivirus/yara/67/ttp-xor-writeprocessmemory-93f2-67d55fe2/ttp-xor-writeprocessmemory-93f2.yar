rule TTP_XOR_WriteProcessMemory_93f2 {
  strings:
    $key_93f2 = { c4 80 [2] f6 a2 [2] f0 97 [2] de 97 [2] e1 8b }

  condition:
    any of them
}