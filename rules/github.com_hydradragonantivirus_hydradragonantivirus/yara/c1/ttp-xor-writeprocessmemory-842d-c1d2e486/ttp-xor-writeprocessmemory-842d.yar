rule TTP_XOR_WriteProcessMemory_842d {
  strings:
    $key_842d = { d3 5f [2] e1 7d [2] e7 48 [2] c9 48 [2] f6 54 }

  condition:
    any of them
}