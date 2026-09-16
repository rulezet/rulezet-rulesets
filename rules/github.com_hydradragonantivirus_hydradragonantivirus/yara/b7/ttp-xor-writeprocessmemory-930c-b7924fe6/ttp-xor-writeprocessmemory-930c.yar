rule TTP_XOR_WriteProcessMemory_930c {
  strings:
    $key_930c = { c4 7e [2] f6 5c [2] f0 69 [2] de 69 [2] e1 75 }

  condition:
    any of them
}