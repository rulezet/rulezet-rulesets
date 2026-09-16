rule TTP_XOR_WriteProcessMemory_1d45 {
  strings:
    $key_1d45 = { 4a 37 [2] 78 15 [2] 7e 20 [2] 50 20 [2] 6f 3c }

  condition:
    any of them
}