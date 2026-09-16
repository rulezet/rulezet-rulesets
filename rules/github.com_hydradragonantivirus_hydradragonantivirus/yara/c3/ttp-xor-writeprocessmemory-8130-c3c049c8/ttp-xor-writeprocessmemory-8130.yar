rule TTP_XOR_WriteProcessMemory_8130 {
  strings:
    $key_8130 = { d6 42 [2] e4 60 [2] e2 55 [2] cc 55 [2] f3 49 }

  condition:
    any of them
}