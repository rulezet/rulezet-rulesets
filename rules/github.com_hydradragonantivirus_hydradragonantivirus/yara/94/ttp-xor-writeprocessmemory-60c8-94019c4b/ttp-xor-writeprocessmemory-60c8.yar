rule TTP_XOR_WriteProcessMemory_60c8 {
  strings:
    $key_60c8 = { 37 ba [2] 05 98 [2] 03 ad [2] 2d ad [2] 12 b1 }

  condition:
    any of them
}