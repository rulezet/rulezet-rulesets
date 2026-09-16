rule TTP_XOR_WriteProcessMemory_478e {
  strings:
    $key_478e = { 10 fc [2] 22 de [2] 24 eb [2] 0a eb [2] 35 f7 }

  condition:
    any of them
}