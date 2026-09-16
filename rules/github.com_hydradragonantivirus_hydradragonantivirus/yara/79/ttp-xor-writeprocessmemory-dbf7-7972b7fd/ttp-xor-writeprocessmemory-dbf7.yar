rule TTP_XOR_WriteProcessMemory_dbf7 {
  strings:
    $key_dbf7 = { 8c 85 [2] be a7 [2] b8 92 [2] 96 92 [2] a9 8e }

  condition:
    any of them
}