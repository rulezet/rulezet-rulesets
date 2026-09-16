rule TTP_XOR_WriteProcessMemory_2272 {
  strings:
    $key_2272 = { 75 00 [2] 47 22 [2] 41 17 [2] 6f 17 [2] 50 0b }

  condition:
    any of them
}