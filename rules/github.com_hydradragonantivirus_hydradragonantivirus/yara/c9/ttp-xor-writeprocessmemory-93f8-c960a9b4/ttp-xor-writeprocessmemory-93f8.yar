rule TTP_XOR_WriteProcessMemory_93f8 {
  strings:
    $key_93f8 = { c4 8a [2] f6 a8 [2] f0 9d [2] de 9d [2] e1 81 }

  condition:
    any of them
}