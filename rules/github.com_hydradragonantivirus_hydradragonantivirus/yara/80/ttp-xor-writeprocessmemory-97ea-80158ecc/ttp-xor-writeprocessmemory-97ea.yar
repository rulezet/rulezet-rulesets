rule TTP_XOR_WriteProcessMemory_97ea {
  strings:
    $key_97ea = { c0 98 [2] f2 ba [2] f4 8f [2] da 8f [2] e5 93 }

  condition:
    any of them
}