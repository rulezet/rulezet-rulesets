rule TTP_XOR_WriteProcessMemory_6441 {
  strings:
    $key_6441 = { 33 33 [2] 01 11 [2] 07 24 [2] 29 24 [2] 16 38 }

  condition:
    any of them
}