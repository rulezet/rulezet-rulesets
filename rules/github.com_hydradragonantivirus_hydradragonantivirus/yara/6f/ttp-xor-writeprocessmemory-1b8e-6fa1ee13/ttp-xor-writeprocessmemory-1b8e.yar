rule TTP_XOR_WriteProcessMemory_1b8e {
  strings:
    $key_1b8e = { 4c fc [2] 7e de [2] 78 eb [2] 56 eb [2] 69 f7 }

  condition:
    any of them
}