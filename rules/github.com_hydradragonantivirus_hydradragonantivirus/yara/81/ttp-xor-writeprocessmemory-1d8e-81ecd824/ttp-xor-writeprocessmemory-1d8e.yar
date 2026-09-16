rule TTP_XOR_WriteProcessMemory_1d8e {
  strings:
    $key_1d8e = { 4a fc [2] 78 de [2] 7e eb [2] 50 eb [2] 6f f7 }

  condition:
    any of them
}