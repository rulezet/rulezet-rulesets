rule TTP_XOR_WriteProcessMemory_5463 {
  strings:
    $key_5463 = { 03 11 [2] 31 33 [2] 37 06 [2] 19 06 [2] 26 1a }

  condition:
    any of them
}