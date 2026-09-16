rule TTP_XOR_WriteProcessMemory_8125 {
  strings:
    $key_8125 = { d6 57 [2] e4 75 [2] e2 40 [2] cc 40 [2] f3 5c }

  condition:
    any of them
}