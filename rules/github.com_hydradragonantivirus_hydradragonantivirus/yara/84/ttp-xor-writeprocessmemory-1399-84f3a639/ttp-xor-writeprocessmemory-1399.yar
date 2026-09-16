rule TTP_XOR_WriteProcessMemory_1399 {
  strings:
    $key_1399 = { 44 eb [2] 76 c9 [2] 70 fc [2] 5e fc [2] 61 e0 }

  condition:
    any of them
}