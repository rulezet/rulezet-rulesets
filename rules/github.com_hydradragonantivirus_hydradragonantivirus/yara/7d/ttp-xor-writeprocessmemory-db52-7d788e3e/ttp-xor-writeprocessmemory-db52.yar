rule TTP_XOR_WriteProcessMemory_db52 {
  strings:
    $key_db52 = { 8c 20 [2] be 02 [2] b8 37 [2] 96 37 [2] a9 2b }

  condition:
    any of them
}