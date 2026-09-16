rule TTP_XOR_WriteProcessMemory_398e {
  strings:
    $key_398e = { 6e fc [2] 5c de [2] 5a eb [2] 74 eb [2] 4b f7 }

  condition:
    any of them
}