rule TTP_XOR_WriteProcessMemory_5b8e {
  strings:
    $key_5b8e = { 0c fc [2] 3e de [2] 38 eb [2] 16 eb [2] 29 f7 }

  condition:
    any of them
}