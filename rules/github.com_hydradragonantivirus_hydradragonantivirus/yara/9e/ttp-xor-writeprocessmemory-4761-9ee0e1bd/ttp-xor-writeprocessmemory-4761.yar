rule TTP_XOR_WriteProcessMemory_4761 {
  strings:
    $key_4761 = { 10 13 [2] 22 31 [2] 24 04 [2] 0a 04 [2] 35 18 }

  condition:
    any of them
}