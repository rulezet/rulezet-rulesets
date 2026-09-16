rule TTP_XOR_WriteProcessMemory_288e {
  strings:
    $key_288e = { 7f fc [2] 4d de [2] 4b eb [2] 65 eb [2] 5a f7 }

  condition:
    any of them
}