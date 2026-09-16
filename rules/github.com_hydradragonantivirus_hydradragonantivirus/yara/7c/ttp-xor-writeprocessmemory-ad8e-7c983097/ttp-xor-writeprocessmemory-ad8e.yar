rule TTP_XOR_WriteProcessMemory_ad8e {
  strings:
    $key_ad8e = { fa fc [2] c8 de [2] ce eb [2] e0 eb [2] df f7 }

  condition:
    any of them
}