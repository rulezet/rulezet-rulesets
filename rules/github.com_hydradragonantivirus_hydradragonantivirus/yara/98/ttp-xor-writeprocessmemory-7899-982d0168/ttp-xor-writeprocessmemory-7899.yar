rule TTP_XOR_WriteProcessMemory_7899 {
  strings:
    $key_7899 = { 2f eb [2] 1d c9 [2] 1b fc [2] 35 fc [2] 0a e0 }

  condition:
    any of them
}