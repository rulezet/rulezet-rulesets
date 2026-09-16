rule TTP_XOR_WriteProcessMemory_6679 {
  strings:
    $key_6679 = { 31 0b [2] 03 29 [2] 05 1c [2] 2b 1c [2] 14 00 }

  condition:
    any of them
}