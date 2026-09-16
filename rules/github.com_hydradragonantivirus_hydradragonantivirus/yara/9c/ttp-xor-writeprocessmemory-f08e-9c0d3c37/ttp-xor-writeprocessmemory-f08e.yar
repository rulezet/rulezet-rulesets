rule TTP_XOR_WriteProcessMemory_f08e {
  strings:
    $key_f08e = { a7 fc [2] 95 de [2] 93 eb [2] bd eb [2] 82 f7 }

  condition:
    any of them
}