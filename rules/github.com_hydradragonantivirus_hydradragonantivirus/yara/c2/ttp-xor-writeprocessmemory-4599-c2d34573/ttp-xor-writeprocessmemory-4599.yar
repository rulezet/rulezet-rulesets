rule TTP_XOR_WriteProcessMemory_4599 {
  strings:
    $key_4599 = { 12 eb [2] 20 c9 [2] 26 fc [2] 08 fc [2] 37 e0 }

  condition:
    any of them
}