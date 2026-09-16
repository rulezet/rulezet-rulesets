rule TTP_XOR_WriteProcessMemory_851c {
  strings:
    $key_851c = { d2 6e [2] e0 4c [2] e6 79 [2] c8 79 [2] f7 65 }

  condition:
    any of them
}