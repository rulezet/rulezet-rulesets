rule TTP_XOR_WriteProcessMemory_018e {
  strings:
    $key_018e = { 56 fc [2] 64 de [2] 62 eb [2] 4c eb [2] 73 f7 }

  condition:
    any of them
}