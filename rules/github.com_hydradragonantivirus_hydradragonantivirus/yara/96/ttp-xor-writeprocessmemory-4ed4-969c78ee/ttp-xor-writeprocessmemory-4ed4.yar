rule TTP_XOR_WriteProcessMemory_4ed4 {
  strings:
    $key_4ed4 = { 19 a6 [2] 2b 84 [2] 2d b1 [2] 03 b1 [2] 3c ad }

  condition:
    any of them
}