rule TTP_XOR_WriteProcessMemory_198e {
  strings:
    $key_198e = { 4e fc [2] 7c de [2] 7a eb [2] 54 eb [2] 6b f7 }

  condition:
    any of them
}