rule TTP_XOR_WriteProcessMemory_0b99 {
  strings:
    $key_0b99 = { 5c eb [2] 6e c9 [2] 68 fc [2] 46 fc [2] 79 e0 }

  condition:
    any of them
}