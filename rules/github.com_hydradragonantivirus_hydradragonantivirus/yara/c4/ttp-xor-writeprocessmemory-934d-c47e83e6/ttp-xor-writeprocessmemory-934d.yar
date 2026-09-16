rule TTP_XOR_WriteProcessMemory_934d {
  strings:
    $key_934d = { c4 3f [2] f6 1d [2] f0 28 [2] de 28 [2] e1 34 }

  condition:
    any of them
}