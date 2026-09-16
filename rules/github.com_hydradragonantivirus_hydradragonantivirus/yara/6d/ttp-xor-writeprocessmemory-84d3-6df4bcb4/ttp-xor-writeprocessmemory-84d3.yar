rule TTP_XOR_WriteProcessMemory_84d3 {
  strings:
    $key_84d3 = { d3 a1 [2] e1 83 [2] e7 b6 [2] c9 b6 [2] f6 aa }

  condition:
    any of them
}