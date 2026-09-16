rule TTP_XOR_WriteProcessMemory_dbf5 {
  strings:
    $key_dbf5 = { 8c 87 [2] be a5 [2] b8 90 [2] 96 90 [2] a9 8c }

  condition:
    any of them
}