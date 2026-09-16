rule TTP_XOR_WriteProcessMemory_1471 {
  strings:
    $key_1471 = { 43 03 [2] 71 21 [2] 77 14 [2] 59 14 [2] 66 08 }

  condition:
    any of them
}