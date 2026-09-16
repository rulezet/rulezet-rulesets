rule TTP_XOR_WriteProcessMemory_5999 {
  strings:
    $key_5999 = { 0e eb [2] 3c c9 [2] 3a fc [2] 14 fc [2] 2b e0 }

  condition:
    any of them
}