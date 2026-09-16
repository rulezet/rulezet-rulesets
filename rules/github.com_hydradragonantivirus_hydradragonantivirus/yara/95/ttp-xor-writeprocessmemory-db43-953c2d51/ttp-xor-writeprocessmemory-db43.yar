rule TTP_XOR_WriteProcessMemory_db43 {
  strings:
    $key_db43 = { 8c 31 [2] be 13 [2] b8 26 [2] 96 26 [2] a9 3a }

  condition:
    any of them
}