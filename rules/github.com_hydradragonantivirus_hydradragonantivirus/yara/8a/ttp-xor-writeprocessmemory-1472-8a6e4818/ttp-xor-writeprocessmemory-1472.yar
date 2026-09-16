rule TTP_XOR_WriteProcessMemory_1472 {
  strings:
    $key_1472 = { 43 00 [2] 71 22 [2] 77 17 [2] 59 17 [2] 66 0b }

  condition:
    any of them
}