rule TTP_XOR_WriteProcessMemory_1448 {
  strings:
    $key_1448 = { 43 3a [2] 71 18 [2] 77 2d [2] 59 2d [2] 66 31 }

  condition:
    any of them
}