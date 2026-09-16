rule TTP_XOR_WriteProcessMemory_84eb {
  strings:
    $key_84eb = { d3 99 [2] e1 bb [2] e7 8e [2] c9 8e [2] f6 92 }

  condition:
    any of them
}