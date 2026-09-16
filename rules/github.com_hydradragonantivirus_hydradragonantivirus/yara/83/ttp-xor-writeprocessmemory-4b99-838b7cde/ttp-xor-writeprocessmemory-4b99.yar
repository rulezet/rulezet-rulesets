rule TTP_XOR_WriteProcessMemory_4b99 {
  strings:
    $key_4b99 = { 1c eb [2] 2e c9 [2] 28 fc [2] 06 fc [2] 39 e0 }

  condition:
    any of them
}