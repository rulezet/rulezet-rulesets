rule TTP_XOR_WriteProcessMemory_e999 {
  strings:
    $key_e999 = { be eb [2] 8c c9 [2] 8a fc [2] a4 fc [2] 9b e0 }

  condition:
    any of them
}