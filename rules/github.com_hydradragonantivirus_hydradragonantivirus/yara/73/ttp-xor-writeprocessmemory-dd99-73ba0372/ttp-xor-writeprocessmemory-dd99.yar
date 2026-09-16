rule TTP_XOR_WriteProcessMemory_dd99 {
  strings:
    $key_dd99 = { 8a eb [2] b8 c9 [2] be fc [2] 90 fc [2] af e0 }

  condition:
    any of them
}