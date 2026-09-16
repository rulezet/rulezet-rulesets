rule TTP_XOR_WriteProcessMemory_60c5 {
  strings:
    $key_60c5 = { 37 b7 [2] 05 95 [2] 03 a0 [2] 2d a0 [2] 12 bc }

  condition:
    any of them
}