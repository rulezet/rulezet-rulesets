rule TTP_XOR_WriteProcessMemory_8401 {
  strings:
    $key_8401 = { d3 73 [2] e1 51 [2] e7 64 [2] c9 64 [2] f6 78 }

  condition:
    any of them
}