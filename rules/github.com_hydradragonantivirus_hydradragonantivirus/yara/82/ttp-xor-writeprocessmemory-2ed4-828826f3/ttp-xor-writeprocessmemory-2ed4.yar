rule TTP_XOR_WriteProcessMemory_2ed4 {
  strings:
    $key_2ed4 = { 79 a6 [2] 4b 84 [2] 4d b1 [2] 63 b1 [2] 5c ad }

  condition:
    any of them
}