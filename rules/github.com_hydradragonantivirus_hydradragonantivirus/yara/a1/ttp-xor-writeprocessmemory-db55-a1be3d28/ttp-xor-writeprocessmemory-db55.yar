rule TTP_XOR_WriteProcessMemory_db55 {
  strings:
    $key_db55 = { 8c 27 [2] be 05 [2] b8 30 [2] 96 30 [2] a9 2c }

  condition:
    any of them
}