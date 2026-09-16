rule TTP_XOR_WriteProcessMemory_97b6 {
  strings:
    $key_97b6 = { c0 c4 [2] f2 e6 [2] f4 d3 [2] da d3 [2] e5 cf }

  condition:
    any of them
}