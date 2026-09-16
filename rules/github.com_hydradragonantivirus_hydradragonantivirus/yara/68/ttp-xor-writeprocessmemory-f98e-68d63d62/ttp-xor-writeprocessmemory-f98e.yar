rule TTP_XOR_WriteProcessMemory_f98e {
  strings:
    $key_f98e = { ae fc [2] 9c de [2] 9a eb [2] b4 eb [2] 8b f7 }

  condition:
    any of them
}