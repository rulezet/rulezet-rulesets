rule TTP_XOR_WriteProcessMemory_8410 {
  strings:
    $key_8410 = { d3 62 [2] e1 40 [2] e7 75 [2] c9 75 [2] f6 69 }

  condition:
    any of them
}