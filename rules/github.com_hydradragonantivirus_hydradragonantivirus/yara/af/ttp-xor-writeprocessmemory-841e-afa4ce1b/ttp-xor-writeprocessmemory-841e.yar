rule TTP_XOR_WriteProcessMemory_841e {
  strings:
    $key_841e = { d3 6c [2] e1 4e [2] e7 7b [2] c9 7b [2] f6 67 }

  condition:
    any of them
}