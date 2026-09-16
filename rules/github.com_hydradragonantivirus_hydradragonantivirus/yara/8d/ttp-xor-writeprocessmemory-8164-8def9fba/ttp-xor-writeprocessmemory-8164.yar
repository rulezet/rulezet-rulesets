rule TTP_XOR_WriteProcessMemory_8164 {
  strings:
    $key_8164 = { d6 16 [2] e4 34 [2] e2 01 [2] cc 01 [2] f3 1d }

  condition:
    any of them
}