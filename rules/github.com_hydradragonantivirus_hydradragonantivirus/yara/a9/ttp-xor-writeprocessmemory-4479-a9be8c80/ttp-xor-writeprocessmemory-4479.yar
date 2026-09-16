rule TTP_XOR_WriteProcessMemory_4479 {
  strings:
    $key_4479 = { 13 0b [2] 21 29 [2] 27 1c [2] 09 1c [2] 36 00 }

  condition:
    any of them
}