rule TTP_XOR_WriteProcessMemory_7699 {
  strings:
    $key_7699 = { 21 eb [2] 13 c9 [2] 15 fc [2] 3b fc [2] 04 e0 }

  condition:
    any of them
}