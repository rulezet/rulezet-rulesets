rule TTP_XOR_WriteProcessMemory_81ee {
  strings:
    $key_81ee = { d6 9c [2] e4 be [2] e2 8b [2] cc 8b [2] f3 97 }

  condition:
    any of them
}