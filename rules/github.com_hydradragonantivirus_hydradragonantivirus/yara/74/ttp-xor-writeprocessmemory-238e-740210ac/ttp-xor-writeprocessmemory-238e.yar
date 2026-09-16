rule TTP_XOR_WriteProcessMemory_238e {
  strings:
    $key_238e = { 74 fc [2] 46 de [2] 40 eb [2] 6e eb [2] 51 f7 }

  condition:
    any of them
}