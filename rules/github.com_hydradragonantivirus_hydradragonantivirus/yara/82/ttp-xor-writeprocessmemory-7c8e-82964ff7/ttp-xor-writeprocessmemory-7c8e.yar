rule TTP_XOR_WriteProcessMemory_7c8e {
  strings:
    $key_7c8e = { 2b fc [2] 19 de [2] 1f eb [2] 31 eb [2] 0e f7 }

  condition:
    any of them
}