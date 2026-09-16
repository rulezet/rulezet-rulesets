rule TTP_XOR_WriteProcessMemory_97d3 {
  strings:
    $key_97d3 = { c0 a1 [2] f2 83 [2] f4 b6 [2] da b6 [2] e5 aa }

  condition:
    any of them
}