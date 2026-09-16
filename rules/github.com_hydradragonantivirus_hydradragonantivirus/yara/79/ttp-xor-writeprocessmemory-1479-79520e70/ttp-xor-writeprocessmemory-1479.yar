rule TTP_XOR_WriteProcessMemory_1479 {
  strings:
    $key_1479 = { 43 0b [2] 71 29 [2] 77 1c [2] 59 1c [2] 66 00 }

  condition:
    any of them
}