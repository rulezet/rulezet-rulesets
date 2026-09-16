rule TTP_XOR_WriteProcessMemory_1d56 {
  strings:
    $key_1d56 = { 4a 24 [2] 78 06 [2] 7e 33 [2] 50 33 [2] 6f 2f }

  condition:
    any of them
}