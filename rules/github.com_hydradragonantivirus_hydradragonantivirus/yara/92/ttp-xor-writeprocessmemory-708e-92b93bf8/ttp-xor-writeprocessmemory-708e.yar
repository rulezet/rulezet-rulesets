rule TTP_XOR_WriteProcessMemory_708e {
  strings:
    $key_708e = { 27 fc [2] 15 de [2] 13 eb [2] 3d eb [2] 02 f7 }

  condition:
    any of them
}