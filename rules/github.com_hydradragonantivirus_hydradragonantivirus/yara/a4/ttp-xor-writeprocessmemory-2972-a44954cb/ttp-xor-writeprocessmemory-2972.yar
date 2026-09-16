rule TTP_XOR_WriteProcessMemory_2972 {
  strings:
    $key_2972 = { 7e 00 [2] 4c 22 [2] 4a 17 [2] 64 17 [2] 5b 0b }

  condition:
    any of them
}