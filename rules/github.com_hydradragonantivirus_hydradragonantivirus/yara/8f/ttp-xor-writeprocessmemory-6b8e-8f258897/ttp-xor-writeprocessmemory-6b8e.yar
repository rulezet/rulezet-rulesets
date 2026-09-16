rule TTP_XOR_WriteProcessMemory_6b8e {
  strings:
    $key_6b8e = { 3c fc [2] 0e de [2] 08 eb [2] 26 eb [2] 19 f7 }

  condition:
    any of them
}