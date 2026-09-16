rule TTP_XOR_WriteProcessMemory_db2b {
  strings:
    $key_db2b = { 8c 59 [2] be 7b [2] b8 4e [2] 96 4e [2] a9 52 }

  condition:
    any of them
}