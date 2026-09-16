rule TTP_XOR_WriteProcessMemory_82d3 {
  strings:
    $key_82d3 = { d5 a1 [2] e7 83 [2] e1 b6 [2] cf b6 [2] f0 aa }

  condition:
    any of them
}