rule TTP_XOR_WriteProcessMemory_842c {
  strings:
    $key_842c = { d3 5e [2] e1 7c [2] e7 49 [2] c9 49 [2] f6 55 }

  condition:
    any of them
}