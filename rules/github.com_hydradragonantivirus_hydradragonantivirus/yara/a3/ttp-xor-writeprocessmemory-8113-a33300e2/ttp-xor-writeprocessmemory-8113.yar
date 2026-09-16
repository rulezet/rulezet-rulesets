rule TTP_XOR_WriteProcessMemory_8113 {
  strings:
    $key_8113 = { d6 61 [2] e4 43 [2] e2 76 [2] cc 76 [2] f3 6a }

  condition:
    any of them
}