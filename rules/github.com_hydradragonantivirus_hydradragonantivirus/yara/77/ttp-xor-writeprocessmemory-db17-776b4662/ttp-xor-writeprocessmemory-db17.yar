rule TTP_XOR_WriteProcessMemory_db17 {
  strings:
    $key_db17 = { 8c 65 [2] be 47 [2] b8 72 [2] 96 72 [2] a9 6e }

  condition:
    any of them
}