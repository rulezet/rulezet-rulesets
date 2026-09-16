rule TTP_XOR_WriteProcessMemory_688e {
  strings:
    $key_688e = { 3f fc [2] 0d de [2] 0b eb [2] 25 eb [2] 1a f7 }

  condition:
    any of them
}