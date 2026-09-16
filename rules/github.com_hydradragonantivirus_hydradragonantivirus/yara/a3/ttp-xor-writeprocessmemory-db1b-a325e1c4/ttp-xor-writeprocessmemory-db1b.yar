rule TTP_XOR_WriteProcessMemory_db1b {
  strings:
    $key_db1b = { 8c 69 [2] be 4b [2] b8 7e [2] 96 7e [2] a9 62 }

  condition:
    any of them
}