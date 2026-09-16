rule TTP_XOR_WriteProcessMemory_dbfc {
  strings:
    $key_dbfc = { 8c 8e [2] be ac [2] b8 99 [2] 96 99 [2] a9 85 }

  condition:
    any of them
}