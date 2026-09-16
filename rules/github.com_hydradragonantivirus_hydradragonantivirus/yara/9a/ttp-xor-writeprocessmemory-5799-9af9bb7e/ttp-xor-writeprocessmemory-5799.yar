rule TTP_XOR_WriteProcessMemory_5799 {
  strings:
    $key_5799 = { 00 eb [2] 32 c9 [2] 34 fc [2] 1a fc [2] 25 e0 }

  condition:
    any of them
}