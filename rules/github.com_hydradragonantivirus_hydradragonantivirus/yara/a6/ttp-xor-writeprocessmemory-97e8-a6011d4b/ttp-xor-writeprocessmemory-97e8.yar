rule TTP_XOR_WriteProcessMemory_97e8 {
  strings:
    $key_97e8 = { c0 9a [2] f2 b8 [2] f4 8d [2] da 8d [2] e5 91 }

  condition:
    any of them
}