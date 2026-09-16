rule TTP_XOR_WriteProcessMemory_148e {
  strings:
    $key_148e = { 43 fc [2] 71 de [2] 77 eb [2] 59 eb [2] 66 f7 }

  condition:
    any of them
}