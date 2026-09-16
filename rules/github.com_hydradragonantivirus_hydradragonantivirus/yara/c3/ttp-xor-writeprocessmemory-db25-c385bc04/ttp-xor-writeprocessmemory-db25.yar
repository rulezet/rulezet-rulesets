rule TTP_XOR_WriteProcessMemory_db25 {
  strings:
    $key_db25 = { 8c 57 [2] be 75 [2] b8 40 [2] 96 40 [2] a9 5c }

  condition:
    any of them
}