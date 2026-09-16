rule TTP_XOR_WriteProcessMemory_97e3 {
  strings:
    $key_97e3 = { c0 91 [2] f2 b3 [2] f4 86 [2] da 86 [2] e5 9a }

  condition:
    any of them
}