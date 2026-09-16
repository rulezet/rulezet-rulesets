rule TTP_XOR_WriteProcessMemory_dbac {
  strings:
    $key_dbac = { 8c de [2] be fc [2] b8 c9 [2] 96 c9 [2] a9 d5 }

  condition:
    any of them
}