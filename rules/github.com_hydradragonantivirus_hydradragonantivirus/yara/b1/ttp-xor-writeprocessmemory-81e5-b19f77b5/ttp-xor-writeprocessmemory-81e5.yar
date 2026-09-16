rule TTP_XOR_WriteProcessMemory_81e5 {
  strings:
    $key_81e5 = { d6 97 [2] e4 b5 [2] e2 80 [2] cc 80 [2] f3 9c }

  condition:
    any of them
}