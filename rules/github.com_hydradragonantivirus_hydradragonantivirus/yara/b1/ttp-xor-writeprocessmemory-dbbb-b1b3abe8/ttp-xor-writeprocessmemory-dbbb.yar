rule TTP_XOR_WriteProcessMemory_dbbb {
  strings:
    $key_dbbb = { 8c c9 [2] be eb [2] b8 de [2] 96 de [2] a9 c2 }

  condition:
    any of them
}