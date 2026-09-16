rule TTP_XOR_WriteProcessMemory_138e {
  strings:
    $key_138e = { 44 fc [2] 76 de [2] 70 eb [2] 5e eb [2] 61 f7 }

  condition:
    any of them
}