rule TTP_XOR_WriteProcessMemory_5652 {
  strings:
    $key_5652 = { 01 20 [2] 33 02 [2] 35 37 [2] 1b 37 [2] 24 2b }

  condition:
    any of them
}