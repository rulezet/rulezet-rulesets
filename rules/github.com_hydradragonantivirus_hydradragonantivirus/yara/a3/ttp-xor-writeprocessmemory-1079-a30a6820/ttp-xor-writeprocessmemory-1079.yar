rule TTP_XOR_WriteProcessMemory_1079 {
  strings:
    $key_1079 = { 47 0b [2] 75 29 [2] 73 1c [2] 5d 1c [2] 62 00 }

  condition:
    any of them
}