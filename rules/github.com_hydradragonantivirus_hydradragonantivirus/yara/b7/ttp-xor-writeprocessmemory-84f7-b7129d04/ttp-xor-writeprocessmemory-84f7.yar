rule TTP_XOR_WriteProcessMemory_84f7 {
  strings:
    $key_84f7 = { d3 85 [2] e1 a7 [2] e7 92 [2] c9 92 [2] f6 8e }

  condition:
    any of them
}