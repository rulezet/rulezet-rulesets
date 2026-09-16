rule TTP_XOR_WriteProcessMemory_1625 {
  strings:
    $key_1625 = { 41 57 [2] 73 75 [2] 75 40 [2] 5b 40 [2] 64 5c }

  condition:
    any of them
}