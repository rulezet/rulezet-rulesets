rule TTP_XOR_WriteProcessMemory_c88e {
  strings:
    $key_c88e = { 9f fc [2] ad de [2] ab eb [2] 85 eb [2] ba f7 }

  condition:
    any of them
}