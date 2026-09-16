rule TTP_XOR_WriteProcessMemory_1b99 {
  strings:
    $key_1b99 = { 4c eb [2] 7e c9 [2] 78 fc [2] 56 fc [2] 69 e0 }

  condition:
    any of them
}