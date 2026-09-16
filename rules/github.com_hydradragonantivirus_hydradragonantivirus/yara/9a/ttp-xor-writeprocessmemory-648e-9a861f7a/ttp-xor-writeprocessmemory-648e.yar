rule TTP_XOR_WriteProcessMemory_648e {
  strings:
    $key_648e = { 33 fc [2] 01 de [2] 07 eb [2] 29 eb [2] 16 f7 }

  condition:
    any of them
}