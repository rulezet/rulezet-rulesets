rule TTP_XOR_WriteProcessMemory_608e {
  strings:
    $key_608e = { 37 fc [2] 05 de [2] 03 eb [2] 2d eb [2] 12 f7 }

  condition:
    any of them
}