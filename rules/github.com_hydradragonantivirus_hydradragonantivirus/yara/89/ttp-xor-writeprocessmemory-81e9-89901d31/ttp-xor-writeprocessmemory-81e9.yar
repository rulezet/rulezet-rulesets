rule TTP_XOR_WriteProcessMemory_81e9 {
  strings:
    $key_81e9 = { d6 9b [2] e4 b9 [2] e2 8c [2] cc 8c [2] f3 90 }

  condition:
    any of them
}