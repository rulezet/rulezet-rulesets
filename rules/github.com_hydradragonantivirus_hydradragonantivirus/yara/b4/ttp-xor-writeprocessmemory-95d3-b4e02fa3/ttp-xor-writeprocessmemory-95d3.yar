rule TTP_XOR_WriteProcessMemory_95d3 {
  strings:
    $key_95d3 = { c2 a1 [2] f0 83 [2] f6 b6 [2] d8 b6 [2] e7 aa }

  condition:
    any of them
}