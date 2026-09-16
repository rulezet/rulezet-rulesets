rule TTP_XOR_WriteProcessMemory_268e {
  strings:
    $key_268e = { 71 fc [2] 43 de [2] 45 eb [2] 6b eb [2] 54 f7 }

  condition:
    any of them
}