rule TTP_XOR_WriteProcessMemory_db15 {
  strings:
    $key_db15 = { 8c 67 [2] be 45 [2] b8 70 [2] 96 70 [2] a9 6c }

  condition:
    any of them
}