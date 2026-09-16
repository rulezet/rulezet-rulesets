rule TTP_XOR_WriteProcessMemory_4a8e {
  strings:
    $key_4a8e = { 1d fc [2] 2f de [2] 29 eb [2] 07 eb [2] 38 f7 }

  condition:
    any of them
}