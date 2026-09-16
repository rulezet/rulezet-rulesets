rule TTP_XOR_WriteProcessMemory_368e {
  strings:
    $key_368e = { 61 fc [2] 53 de [2] 55 eb [2] 7b eb [2] 44 f7 }

  condition:
    any of them
}