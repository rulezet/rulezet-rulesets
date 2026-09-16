rule TTP_XOR_WriteProcessMemory_82b6 {
  strings:
    $key_82b6 = { d5 c4 [2] e7 e6 [2] e1 d3 [2] cf d3 [2] f0 cf }

  condition:
    any of them
}