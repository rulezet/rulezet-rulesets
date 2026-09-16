rule TTP_XOR_WriteProcessMemory_60c0 {
  strings:
    $key_60c0 = { 37 b2 [2] 05 90 [2] 03 a5 [2] 2d a5 [2] 12 b9 }

  condition:
    any of them
}