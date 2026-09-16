rule TTP_XOR_WriteProcessMemory_4365 {
  strings:
    $key_4365 = { 14 17 [2] 26 35 [2] 20 00 [2] 0e 00 [2] 31 1c }

  condition:
    any of them
}