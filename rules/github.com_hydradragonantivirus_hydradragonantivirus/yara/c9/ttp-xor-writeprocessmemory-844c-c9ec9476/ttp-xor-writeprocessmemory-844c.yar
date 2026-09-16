rule TTP_XOR_WriteProcessMemory_844c {
  strings:
    $key_844c = { d3 3e [2] e1 1c [2] e7 29 [2] c9 29 [2] f6 35 }

  condition:
    any of them
}