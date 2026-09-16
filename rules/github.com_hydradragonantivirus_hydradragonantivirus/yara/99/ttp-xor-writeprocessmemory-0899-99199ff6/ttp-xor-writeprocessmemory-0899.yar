rule TTP_XOR_WriteProcessMemory_0899 {
  strings:
    $key_0899 = { 5f eb [2] 6d c9 [2] 6b fc [2] 45 fc [2] 7a e0 }

  condition:
    any of them
}