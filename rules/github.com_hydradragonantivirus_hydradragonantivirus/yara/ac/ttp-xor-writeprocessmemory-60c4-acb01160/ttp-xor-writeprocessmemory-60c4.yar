rule TTP_XOR_WriteProcessMemory_60c4 {
  strings:
    $key_60c4 = { 37 b6 [2] 05 94 [2] 03 a1 [2] 2d a1 [2] 12 bd }

  condition:
    any of them
}