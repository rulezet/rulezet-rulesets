rule TTP_XOR_WriteProcessMemory_8416 {
  strings:
    $key_8416 = { d3 64 [2] e1 46 [2] e7 73 [2] c9 73 [2] f6 6f }

  condition:
    any of them
}