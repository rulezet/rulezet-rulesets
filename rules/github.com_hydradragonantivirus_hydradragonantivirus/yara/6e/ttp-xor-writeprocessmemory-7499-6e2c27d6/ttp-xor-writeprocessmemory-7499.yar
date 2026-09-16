rule TTP_XOR_WriteProcessMemory_7499 {
  strings:
    $key_7499 = { 23 eb [2] 11 c9 [2] 17 fc [2] 39 fc [2] 06 e0 }

  condition:
    any of them
}