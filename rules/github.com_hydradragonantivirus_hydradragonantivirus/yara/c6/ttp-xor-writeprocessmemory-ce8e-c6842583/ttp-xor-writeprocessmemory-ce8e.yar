rule TTP_XOR_WriteProcessMemory_ce8e {
  strings:
    $key_ce8e = { 99 fc [2] ab de [2] ad eb [2] 83 eb [2] bc f7 }

  condition:
    any of them
}