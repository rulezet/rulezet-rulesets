rule TTP_XOR_WriteProcessMemory_1199 {
  strings:
    $key_1199 = { 46 eb [2] 74 c9 [2] 72 fc [2] 5c fc [2] 63 e0 }

  condition:
    any of them
}