rule TTP_XOR_WriteProcessMemory_3599 {
  strings:
    $key_3599 = { 62 eb [2] 50 c9 [2] 56 fc [2] 78 fc [2] 47 e0 }

  condition:
    any of them
}