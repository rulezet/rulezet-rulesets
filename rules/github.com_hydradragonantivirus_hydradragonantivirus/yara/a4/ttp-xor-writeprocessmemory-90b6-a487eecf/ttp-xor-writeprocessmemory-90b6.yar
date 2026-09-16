rule TTP_XOR_WriteProcessMemory_90b6 {
  strings:
    $key_90b6 = { c7 c4 [2] f5 e6 [2] f3 d3 [2] dd d3 [2] e2 cf }

  condition:
    any of them
}