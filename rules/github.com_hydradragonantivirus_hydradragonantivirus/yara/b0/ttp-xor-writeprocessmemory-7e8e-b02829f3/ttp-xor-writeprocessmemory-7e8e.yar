rule TTP_XOR_WriteProcessMemory_7e8e {
  strings:
    $key_7e8e = { 29 fc [2] 1b de [2] 1d eb [2] 33 eb [2] 0c f7 }

  condition:
    any of them
}