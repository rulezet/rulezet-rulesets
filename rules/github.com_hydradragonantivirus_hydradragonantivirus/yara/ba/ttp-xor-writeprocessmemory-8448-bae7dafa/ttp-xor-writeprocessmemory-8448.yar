rule TTP_XOR_WriteProcessMemory_8448 {
  strings:
    $key_8448 = { d3 3a [2] e1 18 [2] e7 2d [2] c9 2d [2] f6 31 }

  condition:
    any of them
}