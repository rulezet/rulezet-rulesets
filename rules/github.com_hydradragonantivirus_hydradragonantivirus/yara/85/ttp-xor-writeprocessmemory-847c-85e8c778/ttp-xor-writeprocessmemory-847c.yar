rule TTP_XOR_WriteProcessMemory_847c {
  strings:
    $key_847c = { d3 0e [2] e1 2c [2] e7 19 [2] c9 19 [2] f6 05 }

  condition:
    any of them
}