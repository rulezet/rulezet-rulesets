rule TTP_XOR_WriteProcessMemory_4079 {
  strings:
    $key_4079 = { 17 0b [2] 25 29 [2] 23 1c [2] 0d 1c [2] 32 00 }

  condition:
    any of them
}