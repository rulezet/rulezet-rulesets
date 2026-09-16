rule TTP_XOR_WriteProcessMemory_6e8e {
  strings:
    $key_6e8e = { 39 fc [2] 0b de [2] 0d eb [2] 23 eb [2] 1c f7 }

  condition:
    any of them
}