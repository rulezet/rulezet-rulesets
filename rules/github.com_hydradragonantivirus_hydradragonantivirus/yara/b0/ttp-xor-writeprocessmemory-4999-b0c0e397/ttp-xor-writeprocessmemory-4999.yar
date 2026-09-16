rule TTP_XOR_WriteProcessMemory_4999 {
  strings:
    $key_4999 = { 1e eb [2] 2c c9 [2] 2a fc [2] 04 fc [2] 3b e0 }

  condition:
    any of them
}