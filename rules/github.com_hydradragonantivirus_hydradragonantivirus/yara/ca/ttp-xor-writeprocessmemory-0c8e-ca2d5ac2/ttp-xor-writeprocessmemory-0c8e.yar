rule TTP_XOR_WriteProcessMemory_0c8e {
  strings:
    $key_0c8e = { 5b fc [2] 69 de [2] 6f eb [2] 41 eb [2] 7e f7 }

  condition:
    any of them
}