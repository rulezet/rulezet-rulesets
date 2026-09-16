rule TTP_XOR_WriteProcessMemory_846c {
  strings:
    $key_846c = { d3 1e [2] e1 3c [2] e7 09 [2] c9 09 [2] f6 15 }

  condition:
    any of them
}