rule TTP_XOR_WriteProcessMemory_4379 {
  strings:
    $key_4379 = { 14 0b [2] 26 29 [2] 20 1c [2] 0e 1c [2] 31 00 }

  condition:
    any of them
}