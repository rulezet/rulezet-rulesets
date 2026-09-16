rule TTP_XOR_WriteProcessMemory_db99 {
  strings:
    $key_db99 = { 8c eb [2] be c9 [2] b8 fc [2] 96 fc [2] a9 e0 }

  condition:
    any of them
}