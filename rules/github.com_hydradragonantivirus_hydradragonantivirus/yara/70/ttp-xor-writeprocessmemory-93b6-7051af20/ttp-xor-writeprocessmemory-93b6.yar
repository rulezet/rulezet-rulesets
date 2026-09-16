rule TTP_XOR_WriteProcessMemory_93b6 {
  strings:
    $key_93b6 = { c4 c4 [2] f6 e6 [2] f0 d3 [2] de d3 [2] e1 cf }

  condition:
    any of them
}