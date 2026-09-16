rule TTP_XOR_WriteProcessMemory_8152 {
  strings:
    $key_8152 = { d6 20 [2] e4 02 [2] e2 37 [2] cc 37 [2] f3 2b }

  condition:
    any of them
}