rule TTP_XOR_WriteProcessMemory_7d99 {
  strings:
    $key_7d99 = { 2a eb [2] 18 c9 [2] 1e fc [2] 30 fc [2] 0f e0 }

  condition:
    any of them
}