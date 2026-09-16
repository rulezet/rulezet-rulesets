rule TTP_XOR_WriteProcessMemory_90d3 {
  strings:
    $key_90d3 = { c7 a1 [2] f5 83 [2] f3 b6 [2] dd b6 [2] e2 aa }

  condition:
    any of them
}