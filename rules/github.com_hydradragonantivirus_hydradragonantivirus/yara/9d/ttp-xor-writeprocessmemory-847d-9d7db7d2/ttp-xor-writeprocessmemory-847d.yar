rule TTP_XOR_WriteProcessMemory_847d {
  strings:
    $key_847d = { d3 0f [2] e1 2d [2] e7 18 [2] c9 18 [2] f6 04 }

  condition:
    any of them
}