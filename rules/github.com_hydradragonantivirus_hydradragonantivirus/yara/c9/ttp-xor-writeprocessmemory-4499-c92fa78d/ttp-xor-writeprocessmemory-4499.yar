rule TTP_XOR_WriteProcessMemory_4499 {
  strings:
    $key_4499 = { 13 eb [2] 21 c9 [2] 27 fc [2] 09 fc [2] 36 e0 }

  condition:
    any of them
}