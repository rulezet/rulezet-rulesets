rule TTP_XOR_WriteProcessMemory_4a99 {
  strings:
    $key_4a99 = { 1d eb [2] 2f c9 [2] 29 fc [2] 07 fc [2] 38 e0 }

  condition:
    any of them
}