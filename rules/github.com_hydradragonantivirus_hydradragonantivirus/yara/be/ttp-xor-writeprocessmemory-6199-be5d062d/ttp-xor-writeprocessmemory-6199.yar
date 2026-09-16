rule TTP_XOR_WriteProcessMemory_6199 {
  strings:
    $key_6199 = { 36 eb [2] 04 c9 [2] 02 fc [2] 2c fc [2] 13 e0 }

  condition:
    any of them
}