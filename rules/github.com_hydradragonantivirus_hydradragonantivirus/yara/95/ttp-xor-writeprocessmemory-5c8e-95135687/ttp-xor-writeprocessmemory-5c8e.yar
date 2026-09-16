rule TTP_XOR_WriteProcessMemory_5c8e {
  strings:
    $key_5c8e = { 0b fc [2] 39 de [2] 3f eb [2] 11 eb [2] 2e f7 }

  condition:
    any of them
}