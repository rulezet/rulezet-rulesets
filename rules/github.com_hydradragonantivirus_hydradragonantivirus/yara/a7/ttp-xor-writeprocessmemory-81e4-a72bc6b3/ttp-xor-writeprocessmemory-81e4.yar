rule TTP_XOR_WriteProcessMemory_81e4 {
  strings:
    $key_81e4 = { d6 96 [2] e4 b4 [2] e2 81 [2] cc 81 [2] f3 9d }

  condition:
    any of them
}