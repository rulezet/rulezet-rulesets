rule TTP_XOR_WriteProcessMemory_95b6 {
  strings:
    $key_95b6 = { c2 c4 [2] f0 e6 [2] f6 d3 [2] d8 d3 [2] e7 cf }

  condition:
    any of them
}