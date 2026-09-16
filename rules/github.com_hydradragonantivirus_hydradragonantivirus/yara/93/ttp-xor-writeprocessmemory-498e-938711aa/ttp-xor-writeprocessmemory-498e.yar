rule TTP_XOR_WriteProcessMemory_498e {
  strings:
    $key_498e = { 1e fc [2] 2c de [2] 2a eb [2] 04 eb [2] 3b f7 }

  condition:
    any of them
}