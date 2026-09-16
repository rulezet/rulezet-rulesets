rule TTP_XOR_WriteProcessMemory_db63 {
  strings:
    $key_db63 = { 8c 11 [2] be 33 [2] b8 06 [2] 96 06 [2] a9 1a }

  condition:
    any of them
}