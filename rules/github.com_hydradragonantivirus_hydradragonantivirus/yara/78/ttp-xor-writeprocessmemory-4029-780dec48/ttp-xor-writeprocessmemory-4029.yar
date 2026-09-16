rule TTP_XOR_WriteProcessMemory_4029 {
  strings:
    $key_4029 = { 17 5b [2] 25 79 [2] 23 4c [2] 0d 4c [2] 32 50 }

  condition:
    any of them
}