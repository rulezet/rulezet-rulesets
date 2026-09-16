rule TTP_XOR_WriteProcessMemory_2199 {
  strings:
    $key_2199 = { 76 eb [2] 44 c9 [2] 42 fc [2] 6c fc [2] 53 e0 }

  condition:
    any of them
}