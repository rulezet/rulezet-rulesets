rule TTP_XOR_WriteProcessMemory_c899 {
  strings:
    $key_c899 = { 9f eb [2] ad c9 [2] ab fc [2] 85 fc [2] ba e0 }

  condition:
    any of them
}