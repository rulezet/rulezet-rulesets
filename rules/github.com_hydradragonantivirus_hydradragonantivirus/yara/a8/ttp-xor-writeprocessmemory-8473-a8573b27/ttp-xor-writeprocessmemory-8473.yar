rule TTP_XOR_WriteProcessMemory_8473 {
  strings:
    $key_8473 = { d3 01 [2] e1 23 [2] e7 16 [2] c9 16 [2] f6 0a }

  condition:
    any of them
}