rule TTP_XOR_WriteProcessMemory_5d99 {
  strings:
    $key_5d99 = { 0a eb [2] 38 c9 [2] 3e fc [2] 10 fc [2] 2f e0 }

  condition:
    any of them
}