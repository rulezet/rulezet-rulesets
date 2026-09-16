rule TTP_XOR_WriteProcessMemory_60c7 {
  strings:
    $key_60c7 = { 37 b5 [2] 05 97 [2] 03 a2 [2] 2d a2 [2] 12 be }

  condition:
    any of them
}