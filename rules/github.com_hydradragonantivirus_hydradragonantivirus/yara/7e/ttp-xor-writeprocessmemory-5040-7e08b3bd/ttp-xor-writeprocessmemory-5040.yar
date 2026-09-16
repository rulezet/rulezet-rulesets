rule TTP_XOR_WriteProcessMemory_5040 {
  strings:
    $key_5040 = { 07 32 [2] 35 10 [2] 33 25 [2] 1d 25 [2] 22 39 }

  condition:
    any of them
}