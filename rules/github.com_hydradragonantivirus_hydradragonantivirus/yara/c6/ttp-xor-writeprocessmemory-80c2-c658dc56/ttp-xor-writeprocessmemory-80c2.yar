rule TTP_XOR_WriteProcessMemory_80c2 {
  strings:
    $key_80c2 = { d7 b0 [2] e5 92 [2] e3 a7 [2] cd a7 [2] f2 bb }

  condition:
    any of them
}