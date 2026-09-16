rule TTP_XOR_WriteProcessMemory_598e {
  strings:
    $key_598e = { 0e fc [2] 3c de [2] 3a eb [2] 14 eb [2] 2b f7 }

  condition:
    any of them
}