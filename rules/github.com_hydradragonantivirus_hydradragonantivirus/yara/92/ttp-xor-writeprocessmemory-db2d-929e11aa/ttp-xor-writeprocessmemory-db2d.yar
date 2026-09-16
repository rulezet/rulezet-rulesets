rule TTP_XOR_WriteProcessMemory_db2d {
  strings:
    $key_db2d = { 8c 5f [2] be 7d [2] b8 48 [2] 96 48 [2] a9 54 }

  condition:
    any of them
}