rule TTP_XOR_WriteProcessMemory_db75 {
  strings:
    $key_db75 = { 8c 07 [2] be 25 [2] b8 10 [2] 96 10 [2] a9 0c }

  condition:
    any of them
}