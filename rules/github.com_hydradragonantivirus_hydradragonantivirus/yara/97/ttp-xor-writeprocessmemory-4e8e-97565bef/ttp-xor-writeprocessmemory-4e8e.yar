rule TTP_XOR_WriteProcessMemory_4e8e {
  strings:
    $key_4e8e = { 19 fc [2] 2b de [2] 2d eb [2] 03 eb [2] 3c f7 }

  condition:
    any of them
}