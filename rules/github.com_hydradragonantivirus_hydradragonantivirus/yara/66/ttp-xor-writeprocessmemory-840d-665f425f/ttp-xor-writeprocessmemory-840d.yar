rule TTP_XOR_WriteProcessMemory_840d {
  strings:
    $key_840d = { d3 7f [2] e1 5d [2] e7 68 [2] c9 68 [2] f6 74 }

  condition:
    any of them
}