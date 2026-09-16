rule TTP_XOR_WriteProcessMemory_8402 {
  strings:
    $key_8402 = { d3 70 [2] e1 52 [2] e7 67 [2] c9 67 [2] f6 7b }

  condition:
    any of them
}