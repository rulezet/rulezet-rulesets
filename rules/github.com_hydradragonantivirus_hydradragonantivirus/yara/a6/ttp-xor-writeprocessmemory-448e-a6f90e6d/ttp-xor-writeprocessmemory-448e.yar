rule TTP_XOR_WriteProcessMemory_448e {
  strings:
    $key_448e = { 13 fc [2] 21 de [2] 27 eb [2] 09 eb [2] 36 f7 }

  condition:
    any of them
}