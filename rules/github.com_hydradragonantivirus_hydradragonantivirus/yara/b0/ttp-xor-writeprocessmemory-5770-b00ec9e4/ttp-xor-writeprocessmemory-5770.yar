rule TTP_XOR_WriteProcessMemory_5770 {
  strings:
    $key_5770 = { 00 02 [2] 32 20 [2] 34 15 [2] 1a 15 [2] 25 09 }

  condition:
    any of them
}