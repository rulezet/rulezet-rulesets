rule TTP_XOR_WriteProcessMemory_568e {
  strings:
    $key_568e = { 01 fc [2] 33 de [2] 35 eb [2] 1b eb [2] 24 f7 }

  condition:
    any of them
}