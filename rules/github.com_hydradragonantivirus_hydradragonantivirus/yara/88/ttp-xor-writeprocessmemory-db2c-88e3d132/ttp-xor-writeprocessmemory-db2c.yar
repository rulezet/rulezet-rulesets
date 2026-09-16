rule TTP_XOR_WriteProcessMemory_db2c {
  strings:
    $key_db2c = { 8c 5e [2] be 7c [2] b8 49 [2] 96 49 [2] a9 55 }

  condition:
    any of them
}