rule TTP_XOR_WriteProcessMemory_2d99 {
  strings:
    $key_2d99 = { 7a eb [2] 48 c9 [2] 4e fc [2] 60 fc [2] 5f e0 }

  condition:
    any of them
}