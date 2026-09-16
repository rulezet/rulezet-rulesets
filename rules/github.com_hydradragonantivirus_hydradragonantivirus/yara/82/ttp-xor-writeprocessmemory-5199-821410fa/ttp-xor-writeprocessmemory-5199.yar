rule TTP_XOR_WriteProcessMemory_5199 {
  strings:
    $key_5199 = { 06 eb [2] 34 c9 [2] 32 fc [2] 1c fc [2] 23 e0 }

  condition:
    any of them
}