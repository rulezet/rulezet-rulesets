rule TTP_XOR_WriteProcessMemory_2599 {
  strings:
    $key_2599 = { 72 eb [2] 40 c9 [2] 46 fc [2] 68 fc [2] 57 e0 }

  condition:
    any of them
}