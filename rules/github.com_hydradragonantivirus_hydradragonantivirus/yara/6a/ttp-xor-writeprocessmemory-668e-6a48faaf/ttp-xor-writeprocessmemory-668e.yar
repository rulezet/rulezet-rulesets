rule TTP_XOR_WriteProcessMemory_668e {
  strings:
    $key_668e = { 31 fc [2] 03 de [2] 05 eb [2] 2b eb [2] 14 f7 }

  condition:
    any of them
}