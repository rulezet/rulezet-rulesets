rule TTP_XOR_WriteProcessMemory_81e3 {
  strings:
    $key_81e3 = { d6 91 [2] e4 b3 [2] e2 86 [2] cc 86 [2] f3 9a }

  condition:
    any of them
}