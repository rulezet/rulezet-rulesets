rule TTP_XOR_WriteProcessMemory_0d99 {
  strings:
    $key_0d99 = { 5a eb [2] 68 c9 [2] 6e fc [2] 40 fc [2] 7f e0 }

  condition:
    any of them
}