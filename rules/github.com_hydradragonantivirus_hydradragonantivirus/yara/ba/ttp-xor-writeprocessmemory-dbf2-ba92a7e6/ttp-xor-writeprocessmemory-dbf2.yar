rule TTP_XOR_WriteProcessMemory_dbf2 {
  strings:
    $key_dbf2 = { 8c 80 [2] be a2 [2] b8 97 [2] 96 97 [2] a9 8b }

  condition:
    any of them
}