rule TTP_XOR_WriteProcessMemory_388e {
  strings:
    $key_388e = { 6f fc [2] 5d de [2] 5b eb [2] 75 eb [2] 4a f7 }

  condition:
    any of them
}