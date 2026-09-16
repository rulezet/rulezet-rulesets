rule TTP_XOR_WriteProcessMemory_db45 {
  strings:
    $key_db45 = { 8c 37 [2] be 15 [2] b8 20 [2] 96 20 [2] a9 3c }

  condition:
    any of them
}