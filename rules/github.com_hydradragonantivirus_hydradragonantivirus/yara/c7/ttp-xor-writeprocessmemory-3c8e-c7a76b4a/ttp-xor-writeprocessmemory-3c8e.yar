rule TTP_XOR_WriteProcessMemory_3c8e {
  strings:
    $key_3c8e = { 6b fc [2] 59 de [2] 5f eb [2] 71 eb [2] 4e f7 }

  condition:
    any of them
}