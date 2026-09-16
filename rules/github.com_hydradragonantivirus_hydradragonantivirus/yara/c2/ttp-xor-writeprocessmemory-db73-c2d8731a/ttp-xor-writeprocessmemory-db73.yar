rule TTP_XOR_WriteProcessMemory_db73 {
  strings:
    $key_db73 = { 8c 01 [2] be 23 [2] b8 16 [2] 96 16 [2] a9 0a }

  condition:
    any of them
}