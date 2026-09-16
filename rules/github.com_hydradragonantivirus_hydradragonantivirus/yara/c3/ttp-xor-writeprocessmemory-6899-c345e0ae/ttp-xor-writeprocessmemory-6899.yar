rule TTP_XOR_WriteProcessMemory_6899 {
  strings:
    $key_6899 = { 3f eb [2] 0d c9 [2] 0b fc [2] 25 fc [2] 1a e0 }

  condition:
    any of them
}