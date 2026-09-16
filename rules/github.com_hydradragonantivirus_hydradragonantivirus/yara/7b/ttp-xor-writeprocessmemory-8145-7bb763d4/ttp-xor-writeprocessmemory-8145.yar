rule TTP_XOR_WriteProcessMemory_8145 {
  strings:
    $key_8145 = { d6 37 [2] e4 15 [2] e2 20 [2] cc 20 [2] f3 3c }

  condition:
    any of them
}