rule TTP_XOR_WriteProcessMemory_5510 {
  strings:
    $key_5510 = { 02 62 [2] 30 40 [2] 36 75 [2] 18 75 [2] 27 69 }

  condition:
    any of them
}