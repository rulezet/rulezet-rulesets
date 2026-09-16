rule TTP_XOR_WriteProcessMemory_5779 {
  strings:
    $key_5779 = { 00 0b [2] 32 29 [2] 34 1c [2] 1a 1c [2] 25 00 }

  condition:
    any of them
}