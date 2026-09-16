rule TTP_XOR_WriteProcessMemory_1645 {
  strings:
    $key_1645 = { 41 37 [2] 73 15 [2] 75 20 [2] 5b 20 [2] 64 3c }

  condition:
    any of them
}