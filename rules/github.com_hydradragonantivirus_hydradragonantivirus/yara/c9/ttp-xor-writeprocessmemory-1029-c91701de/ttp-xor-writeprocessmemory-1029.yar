rule TTP_XOR_WriteProcessMemory_1029 {
  strings:
    $key_1029 = { 47 5b [2] 75 79 [2] 73 4c [2] 5d 4c [2] 62 50 }

  condition:
    any of them
}