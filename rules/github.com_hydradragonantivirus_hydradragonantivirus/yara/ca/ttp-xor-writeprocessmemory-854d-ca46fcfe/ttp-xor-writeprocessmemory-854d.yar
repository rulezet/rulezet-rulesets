rule TTP_XOR_WriteProcessMemory_854d {
  strings:
    $key_854d = { d2 3f [2] e0 1d [2] e6 28 [2] c8 28 [2] f7 34 }

  condition:
    any of them
}