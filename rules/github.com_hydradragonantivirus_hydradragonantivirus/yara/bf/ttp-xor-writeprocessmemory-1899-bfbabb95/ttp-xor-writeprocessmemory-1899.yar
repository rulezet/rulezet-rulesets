rule TTP_XOR_WriteProcessMemory_1899 {
  strings:
    $key_1899 = { 4f eb [2] 7d c9 [2] 7b fc [2] 55 fc [2] 6a e0 }

  condition:
    any of them
}