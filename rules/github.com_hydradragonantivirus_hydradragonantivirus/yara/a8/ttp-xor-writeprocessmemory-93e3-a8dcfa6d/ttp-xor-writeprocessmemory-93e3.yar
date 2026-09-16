rule TTP_XOR_WriteProcessMemory_93e3 {
  strings:
    $key_93e3 = { c4 91 [2] f6 b3 [2] f0 86 [2] de 86 [2] e1 9a }

  condition:
    any of them
}