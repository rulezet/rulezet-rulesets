rule TTP_XOR_WriteProcessMemory_4765 {
  strings:
    $key_4765 = { 10 17 [2] 22 35 [2] 24 00 [2] 0a 00 [2] 35 1c }

  condition:
    any of them
}