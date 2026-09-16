rule TTP_XOR_WriteProcessMemory_5429 {
  strings:
    $key_5429 = { 03 5b [2] 31 79 [2] 37 4c [2] 19 4c [2] 26 50 }

  condition:
    any of them
}