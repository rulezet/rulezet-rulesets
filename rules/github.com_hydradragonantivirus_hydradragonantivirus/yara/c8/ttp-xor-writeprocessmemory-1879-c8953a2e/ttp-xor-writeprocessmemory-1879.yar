rule TTP_XOR_WriteProcessMemory_1879 {
  strings:
    $key_1879 = { 4f 0b [2] 7d 29 [2] 7b 1c [2] 55 1c [2] 6a 00 }

  condition:
    any of them
}