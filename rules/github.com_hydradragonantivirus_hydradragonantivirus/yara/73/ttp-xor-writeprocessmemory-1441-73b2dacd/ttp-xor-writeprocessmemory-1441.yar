rule TTP_XOR_WriteProcessMemory_1441 {
  strings:
    $key_1441 = { 43 33 [2] 71 11 [2] 77 24 [2] 59 24 [2] 66 38 }

  condition:
    any of them
}