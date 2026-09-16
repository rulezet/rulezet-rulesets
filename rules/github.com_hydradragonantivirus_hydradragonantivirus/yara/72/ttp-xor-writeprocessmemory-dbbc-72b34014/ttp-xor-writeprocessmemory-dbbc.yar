rule TTP_XOR_WriteProcessMemory_dbbc {
  strings:
    $key_dbbc = { 8c ce [2] be ec [2] b8 d9 [2] 96 d9 [2] a9 c5 }

  condition:
    any of them
}