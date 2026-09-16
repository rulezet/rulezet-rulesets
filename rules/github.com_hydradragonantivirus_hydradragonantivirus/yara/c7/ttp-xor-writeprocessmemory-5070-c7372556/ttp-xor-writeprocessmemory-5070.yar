rule TTP_XOR_WriteProcessMemory_5070 {
  strings:
    $key_5070 = { 07 02 [2] 35 20 [2] 33 15 [2] 1d 15 [2] 22 09 }

  condition:
    any of them
}