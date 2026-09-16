rule TTP_XOR_WriteProcessMemory_6d99 {
  strings:
    $key_6d99 = { 3a eb [2] 08 c9 [2] 0e fc [2] 20 fc [2] 1f e0 }

  condition:
    any of them
}