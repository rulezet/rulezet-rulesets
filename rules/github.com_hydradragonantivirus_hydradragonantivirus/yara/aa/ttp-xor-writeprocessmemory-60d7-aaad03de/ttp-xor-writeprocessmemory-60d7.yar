rule TTP_XOR_WriteProcessMemory_60d7 {
  strings:
    $key_60d7 = { 37 a5 [2] 05 87 [2] 03 b2 [2] 2d b2 [2] 12 ae }

  condition:
    any of them
}