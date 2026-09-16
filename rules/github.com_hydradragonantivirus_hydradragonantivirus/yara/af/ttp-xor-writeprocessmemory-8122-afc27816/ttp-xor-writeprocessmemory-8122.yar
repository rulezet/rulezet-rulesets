rule TTP_XOR_WriteProcessMemory_8122 {
  strings:
    $key_8122 = { d6 50 [2] e4 72 [2] e2 47 [2] cc 47 [2] f3 5b }

  condition:
    any of them
}