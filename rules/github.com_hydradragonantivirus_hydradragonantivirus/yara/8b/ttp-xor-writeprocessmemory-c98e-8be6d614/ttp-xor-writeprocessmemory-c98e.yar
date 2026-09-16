rule TTP_XOR_WriteProcessMemory_c98e {
  strings:
    $key_c98e = { 9e fc [2] ac de [2] aa eb [2] 84 eb [2] bb f7 }

  condition:
    any of them
}