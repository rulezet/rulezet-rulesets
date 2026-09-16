rule TTP_XOR_WriteProcessMemory_8438 {
  strings:
    $key_8438 = { d3 4a [2] e1 68 [2] e7 5d [2] c9 5d [2] f6 41 }

  condition:
    any of them
}