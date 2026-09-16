rule TTP_XOR_WriteProcessMemory_5e8e {
  strings:
    $key_5e8e = { 09 fc [2] 3b de [2] 3d eb [2] 13 eb [2] 2c f7 }

  condition:
    any of them
}