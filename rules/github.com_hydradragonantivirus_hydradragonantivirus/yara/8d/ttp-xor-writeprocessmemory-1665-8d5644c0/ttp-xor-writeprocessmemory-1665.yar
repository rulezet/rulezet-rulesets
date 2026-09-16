rule TTP_XOR_WriteProcessMemory_1665 {
  strings:
    $key_1665 = { 41 17 [2] 73 35 [2] 75 00 [2] 5b 00 [2] 64 1c }

  condition:
    any of them
}