rule TTP_XOR_WriteProcessMemory_5a99 {
  strings:
    $key_5a99 = { 0d eb [2] 3f c9 [2] 39 fc [2] 17 fc [2] 28 e0 }

  condition:
    any of them
}