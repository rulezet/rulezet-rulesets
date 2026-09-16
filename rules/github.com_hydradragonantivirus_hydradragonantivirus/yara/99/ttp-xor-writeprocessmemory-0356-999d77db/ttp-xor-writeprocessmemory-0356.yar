rule TTP_XOR_WriteProcessMemory_0356 {
  strings:
    $key_0356 = { 54 24 [2] 66 06 [2] 60 33 [2] 4e 33 [2] 71 2f }

  condition:
    any of them
}