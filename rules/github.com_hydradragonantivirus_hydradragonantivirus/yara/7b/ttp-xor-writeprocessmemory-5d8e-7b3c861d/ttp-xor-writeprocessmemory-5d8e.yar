rule TTP_XOR_WriteProcessMemory_5d8e {
  strings:
    $key_5d8e = { 0a fc [2] 38 de [2] 3e eb [2] 10 eb [2] 2f f7 }

  condition:
    any of them
}