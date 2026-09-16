rule TTP_XOR_WriteProcessMemory_3999 {
  strings:
    $key_3999 = { 6e eb [2] 5c c9 [2] 5a fc [2] 74 fc [2] 4b e0 }

  condition:
    any of them
}