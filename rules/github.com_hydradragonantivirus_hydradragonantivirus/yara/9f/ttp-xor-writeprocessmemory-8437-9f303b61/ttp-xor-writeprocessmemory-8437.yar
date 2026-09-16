rule TTP_XOR_WriteProcessMemory_8437 {
  strings:
    $key_8437 = { d3 45 [2] e1 67 [2] e7 52 [2] c9 52 [2] f6 4e }

  condition:
    any of them
}