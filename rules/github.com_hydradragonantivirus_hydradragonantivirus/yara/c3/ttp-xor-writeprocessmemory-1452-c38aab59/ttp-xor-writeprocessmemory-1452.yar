rule TTP_XOR_WriteProcessMemory_1452 {
  strings:
    $key_1452 = { 43 20 [2] 71 02 [2] 77 37 [2] 59 37 [2] 66 2b }

  condition:
    any of them
}