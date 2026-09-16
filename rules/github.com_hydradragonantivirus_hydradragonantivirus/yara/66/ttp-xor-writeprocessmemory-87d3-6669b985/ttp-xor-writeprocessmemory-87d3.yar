rule TTP_XOR_WriteProcessMemory_87d3 {
  strings:
    $key_87d3 = { d0 a1 [2] e2 83 [2] e4 b6 [2] ca b6 [2] f5 aa }

  condition:
    any of them
}