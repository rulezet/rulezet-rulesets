rule TTP_XOR_WriteProcessMemory_3b8e {
  strings:
    $key_3b8e = { 6c fc [2] 5e de [2] 58 eb [2] 76 eb [2] 49 f7 }

  condition:
    any of them
}