rule TTP_XOR_WriteProcessMemory_208e {
  strings:
    $key_208e = { 77 fc [2] 45 de [2] 43 eb [2] 6d eb [2] 52 f7 }

  condition:
    any of them
}