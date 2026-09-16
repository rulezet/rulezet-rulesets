rule TTP_XOR_WriteProcessMemory_dbfb {
  strings:
    $key_dbfb = { 8c 89 [2] be ab [2] b8 9e [2] 96 9e [2] a9 82 }

  condition:
    any of them
}