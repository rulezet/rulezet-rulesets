rule TTP_XOR_WriteProcessMemory_7560 {
  strings:
    $key_7560 = { 22 12 [2] 10 30 [2] 16 05 [2] 38 05 [2] 07 19 }

  condition:
    any of them
}