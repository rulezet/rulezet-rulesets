rule TTP_XOR_WriteProcessMemory_1461 {
  strings:
    $key_1461 = { 43 13 [2] 71 31 [2] 77 04 [2] 59 04 [2] 66 18 }

  condition:
    any of them
}