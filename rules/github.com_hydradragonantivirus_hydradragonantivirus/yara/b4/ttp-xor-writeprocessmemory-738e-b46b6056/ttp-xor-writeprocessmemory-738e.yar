rule TTP_XOR_WriteProcessMemory_738e {
  strings:
    $key_738e = { 24 fc [2] 16 de [2] 10 eb [2] 3e eb [2] 01 f7 }

  condition:
    any of them
}