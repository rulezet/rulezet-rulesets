rule TTP_XOR_WriteProcessMemory_4423 {
  strings:
    $key_4423 = { 13 51 [2] 21 73 [2] 27 46 [2] 09 46 [2] 36 5a }

  condition:
    any of them
}