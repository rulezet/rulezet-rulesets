rule TTP_XOR_WriteProcessMemory_758e {
  strings:
    $key_758e = { 22 fc [2] 10 de [2] 16 eb [2] 38 eb [2] 07 f7 }

  condition:
    any of them
}