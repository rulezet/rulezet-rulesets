rule TTP_XOR_WriteProcessMemory_5029 {
  strings:
    $key_5029 = { 07 5b [2] 35 79 [2] 33 4c [2] 1d 4c [2] 22 50 }

  condition:
    any of them
}