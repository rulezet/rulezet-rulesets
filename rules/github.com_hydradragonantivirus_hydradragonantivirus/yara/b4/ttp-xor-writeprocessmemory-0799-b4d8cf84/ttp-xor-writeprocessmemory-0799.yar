rule TTP_XOR_WriteProcessMemory_0799 {
  strings:
    $key_0799 = { 50 eb [2] 62 c9 [2] 64 fc [2] 4a fc [2] 75 e0 }

  condition:
    any of them
}