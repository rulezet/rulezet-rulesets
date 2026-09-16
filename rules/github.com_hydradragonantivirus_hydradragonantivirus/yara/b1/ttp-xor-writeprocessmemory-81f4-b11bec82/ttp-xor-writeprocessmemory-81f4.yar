rule TTP_XOR_WriteProcessMemory_81f4 {
  strings:
    $key_81f4 = { d6 86 [2] e4 a4 [2] e2 91 [2] cc 91 [2] f3 8d }

  condition:
    any of them
}