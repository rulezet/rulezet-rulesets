rule TTP_XOR_WriteProcessMemory_5729 {
  strings:
    $key_5729 = { 00 5b [2] 32 79 [2] 34 4c [2] 1a 4c [2] 25 50 }

  condition:
    any of them
}