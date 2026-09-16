rule TTP_XOR_WriteProcessMemory_db56 {
  strings:
    $key_db56 = { 8c 24 [2] be 06 [2] b8 33 [2] 96 33 [2] a9 2f }

  condition:
    any of them
}