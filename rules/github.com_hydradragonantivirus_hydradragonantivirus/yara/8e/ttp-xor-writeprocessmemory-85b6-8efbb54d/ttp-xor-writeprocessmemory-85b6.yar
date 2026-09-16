rule TTP_XOR_WriteProcessMemory_85b6 {
  strings:
    $key_85b6 = { d2 c4 [2] e0 e6 [2] e6 d3 [2] c8 d3 [2] f7 cf }

  condition:
    any of them
}