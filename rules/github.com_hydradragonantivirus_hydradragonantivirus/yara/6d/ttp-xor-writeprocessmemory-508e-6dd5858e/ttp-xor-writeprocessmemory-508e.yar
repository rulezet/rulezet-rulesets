rule TTP_XOR_WriteProcessMemory_508e {
  strings:
    $key_508e = { 07 fc [2] 35 de [2] 33 eb [2] 1d eb [2] 22 f7 }

  condition:
    any of them
}