rule TTP_XOR_WriteProcessMemory_5739 {
  strings:
    $key_5739 = { 00 4b [2] 32 69 [2] 34 5c [2] 1a 5c [2] 25 40 }

  condition:
    any of them
}