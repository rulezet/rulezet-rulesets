rule TTP_XOR_WriteProcessMemory_3b99 {
  strings:
    $key_3b99 = { 6c eb [2] 5e c9 [2] 58 fc [2] 76 fc [2] 49 e0 }

  condition:
    any of them
}