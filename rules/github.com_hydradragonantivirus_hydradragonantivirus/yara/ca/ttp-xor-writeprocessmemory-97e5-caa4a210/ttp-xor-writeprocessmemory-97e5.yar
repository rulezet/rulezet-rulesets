rule TTP_XOR_WriteProcessMemory_97e5 {
  strings:
    $key_97e5 = { c0 97 [2] f2 b5 [2] f4 80 [2] da 80 [2] e5 9c }

  condition:
    any of them
}