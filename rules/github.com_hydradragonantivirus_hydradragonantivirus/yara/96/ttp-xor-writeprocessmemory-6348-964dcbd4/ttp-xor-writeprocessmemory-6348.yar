rule TTP_XOR_WriteProcessMemory_6348 {
  strings:
    $key_6348 = { 34 3a [2] 06 18 [2] 00 2d [2] 2e 2d [2] 11 31 }

  condition:
    any of them
}