rule TTP_XOR_WriteProcessMemory_feac {
  strings:
    $key_feac = { a9 de [2] 9b fc [2] 9d c9 [2] b3 c9 [2] 8c d5 }

  condition:
    any of them
}