rule TTP_XOR_WriteProcessMemory_81d3 {
  strings:
    $key_81d3 = { d6 a1 [2] e4 83 [2] e2 b6 [2] cc b6 [2] f3 aa }

  condition:
    any of them
}