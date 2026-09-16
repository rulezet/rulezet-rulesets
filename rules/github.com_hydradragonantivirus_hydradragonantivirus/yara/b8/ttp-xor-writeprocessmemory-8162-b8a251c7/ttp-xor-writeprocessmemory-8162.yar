rule TTP_XOR_WriteProcessMemory_8162 {
  strings:
    $key_8162 = { d6 10 [2] e4 32 [2] e2 07 [2] cc 07 [2] f3 1b }

  condition:
    any of them
}