rule TTP_XOR_WriteProcessMemory_f88e {
  strings:
    $key_f88e = { af fc [2] 9d de [2] 9b eb [2] b5 eb [2] 8a f7 }

  condition:
    any of them
}