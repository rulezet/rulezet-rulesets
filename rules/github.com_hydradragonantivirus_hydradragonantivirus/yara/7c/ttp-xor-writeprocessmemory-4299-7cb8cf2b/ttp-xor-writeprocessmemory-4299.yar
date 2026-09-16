rule TTP_XOR_WriteProcessMemory_4299 {
  strings:
    $key_4299 = { 15 eb [2] 27 c9 [2] 21 fc [2] 0f fc [2] 30 e0 }

  condition:
    any of them
}