rule TTP_XOR_WriteProcessMemory_84d7 {
  strings:
    $key_84d7 = { d3 a5 [2] e1 87 [2] e7 b2 [2] c9 b2 [2] f6 ae }

  condition:
    any of them
}