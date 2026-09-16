rule TTP_XOR_WriteProcessMemory_5899 {
  strings:
    $key_5899 = { 0f eb [2] 3d c9 [2] 3b fc [2] 15 fc [2] 2a e0 }

  condition:
    any of them
}