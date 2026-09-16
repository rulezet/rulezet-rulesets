rule TTP_XOR_WriteProcessMemory_93ea {
  strings:
    $key_93ea = { c4 98 [2] f6 ba [2] f0 8f [2] de 8f [2] e1 93 }

  condition:
    any of them
}