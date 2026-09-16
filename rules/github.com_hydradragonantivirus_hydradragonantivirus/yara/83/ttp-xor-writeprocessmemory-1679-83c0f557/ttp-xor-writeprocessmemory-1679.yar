rule TTP_XOR_WriteProcessMemory_1679 {
  strings:
    $key_1679 = { 41 0b [2] 73 29 [2] 75 1c [2] 5b 1c [2] 64 00 }

  condition:
    any of them
}