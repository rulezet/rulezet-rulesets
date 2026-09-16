rule TTP_XOR_WriteProcessMemory_db35 {
  strings:
    $key_db35 = { 8c 47 [2] be 65 [2] b8 50 [2] 96 50 [2] a9 4c }

  condition:
    any of them
}