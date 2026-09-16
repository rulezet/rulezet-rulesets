rule TTP_XOR_WriteProcessMemory_60d5 {
  strings:
    $key_60d5 = { 37 a7 [2] 05 85 [2] 03 b0 [2] 2d b0 [2] 12 ac }

  condition:
    any of them
}