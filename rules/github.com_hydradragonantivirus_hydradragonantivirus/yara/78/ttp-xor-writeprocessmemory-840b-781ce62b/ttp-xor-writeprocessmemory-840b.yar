rule TTP_XOR_WriteProcessMemory_840b {
  strings:
    $key_840b = { d3 79 [2] e1 5b [2] e7 6e [2] c9 6e [2] f6 72 }

  condition:
    any of them
}