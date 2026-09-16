rule TTP_XOR_WriteProcessMemory_0765 {
  strings:
    $key_0765 = { 50 17 [2] 62 35 [2] 64 00 [2] 4a 00 [2] 75 1c }

  condition:
    any of them
}