rule TTP_XOR_WriteProcessMemory_5f79 {
  strings:
    $key_5f79 = { 08 0b [2] 3a 29 [2] 3c 1c [2] 12 1c [2] 2d 00 }

  condition:
    any of them
}