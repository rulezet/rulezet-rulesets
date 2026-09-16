rule TTP_XOR_WriteProcessMemory_60c6 {
  strings:
    $key_60c6 = { 37 b4 [2] 05 96 [2] 03 a3 [2] 2d a3 [2] 12 bf }

  condition:
    any of them
}