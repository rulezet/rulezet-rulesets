rule TTP_XOR_WriteProcessMemory_1e8e {
  strings:
    $key_1e8e = { 49 fc [2] 7b de [2] 7d eb [2] 53 eb [2] 6c f7 }

  condition:
    any of them
}