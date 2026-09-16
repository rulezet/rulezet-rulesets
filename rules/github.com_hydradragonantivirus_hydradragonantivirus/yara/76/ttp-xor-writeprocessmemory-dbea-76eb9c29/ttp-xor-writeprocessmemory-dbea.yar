rule TTP_XOR_WriteProcessMemory_dbea {
  strings:
    $key_dbea = { 8c 98 [2] be ba [2] b8 8f [2] 96 8f [2] a9 93 }

  condition:
    any of them
}