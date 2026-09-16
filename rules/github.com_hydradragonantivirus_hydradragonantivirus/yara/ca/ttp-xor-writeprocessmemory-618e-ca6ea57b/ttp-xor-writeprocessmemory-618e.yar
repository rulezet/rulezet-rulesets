rule TTP_XOR_WriteProcessMemory_618e {
  strings:
    $key_618e = { 36 fc [2] 04 de [2] 02 eb [2] 2c eb [2] 13 f7 }

  condition:
    any of them
}