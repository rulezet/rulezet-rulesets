rule TTP_XOR_WriteProcessMemory_933e {
  strings:
    $key_933e = { c4 4c [2] f6 6e [2] f0 5b [2] de 5b [2] e1 47 }

  condition:
    any of them
}