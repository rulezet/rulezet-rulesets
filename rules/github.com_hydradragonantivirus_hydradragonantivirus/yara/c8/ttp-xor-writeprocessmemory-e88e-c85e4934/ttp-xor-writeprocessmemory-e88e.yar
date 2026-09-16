rule TTP_XOR_WriteProcessMemory_e88e {
  strings:
    $key_e88e = { bf fc [2] 8d de [2] 8b eb [2] a5 eb [2] 9a f7 }

  condition:
    any of them
}