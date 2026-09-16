rule TTP_XOR_WriteProcessMemory_842b {
  strings:
    $key_842b = { d3 59 [2] e1 7b [2] e7 4e [2] c9 4e [2] f6 52 }

  condition:
    any of them
}