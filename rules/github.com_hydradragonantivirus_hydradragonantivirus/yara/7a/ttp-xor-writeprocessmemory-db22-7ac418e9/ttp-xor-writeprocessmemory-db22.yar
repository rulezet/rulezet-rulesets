rule TTP_XOR_WriteProcessMemory_db22 {
  strings:
    $key_db22 = { 8c 50 [2] be 72 [2] b8 47 [2] 96 47 [2] a9 5b }

  condition:
    any of them
}