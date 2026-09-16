rule TTP_XOR_WriteProcessMemory_814d {
  strings:
    $key_814d = { d6 3f [2] e4 1d [2] e2 28 [2] cc 28 [2] f3 34 }

  condition:
    any of them
}