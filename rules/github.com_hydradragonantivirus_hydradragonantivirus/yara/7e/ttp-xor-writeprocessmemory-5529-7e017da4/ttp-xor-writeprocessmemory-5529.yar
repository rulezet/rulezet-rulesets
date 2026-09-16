rule TTP_XOR_WriteProcessMemory_5529 {
  strings:
    $key_5529 = { 02 5b [2] 30 79 [2] 36 4c [2] 18 4c [2] 27 50 }

  condition:
    any of them
}