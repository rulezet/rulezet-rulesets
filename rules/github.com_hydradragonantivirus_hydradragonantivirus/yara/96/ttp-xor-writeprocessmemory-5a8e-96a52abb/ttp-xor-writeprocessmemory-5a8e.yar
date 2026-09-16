rule TTP_XOR_WriteProcessMemory_5a8e {
  strings:
    $key_5a8e = { 0d fc [2] 3f de [2] 39 eb [2] 17 eb [2] 28 f7 }

  condition:
    any of them
}