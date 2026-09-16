rule TTP_XOR_WriteProcessMemory_92d3 {
  strings:
    $key_92d3 = { c5 a1 [2] f7 83 [2] f1 b6 [2] df b6 [2] e0 aa }

  condition:
    any of them
}