rule TTP_XOR_WriteProcessMemory_843d {
  strings:
    $key_843d = { d3 4f [2] e1 6d [2] e7 58 [2] c9 58 [2] f6 44 }

  condition:
    any of them
}