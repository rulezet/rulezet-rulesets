rule TTP_XOR_WriteProcessMemory_358e {
  strings:
    $key_358e = { 62 fc [2] 50 de [2] 56 eb [2] 78 eb [2] 47 f7 }

  condition:
    any of them
}