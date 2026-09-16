rule TTP_XOR_WriteProcessMemory_84b9 {
  strings:
    $key_84b9 = { d3 cb [2] e1 e9 [2] e7 dc [2] c9 dc [2] f6 c0 }

  condition:
    any of them
}