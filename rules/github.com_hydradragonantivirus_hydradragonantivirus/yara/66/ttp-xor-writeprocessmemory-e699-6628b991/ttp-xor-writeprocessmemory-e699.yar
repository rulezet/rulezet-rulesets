rule TTP_XOR_WriteProcessMemory_e699 {
  strings:
    $key_e699 = { b1 eb [2] 83 c9 [2] 85 fc [2] ab fc [2] 94 e0 }

  condition:
    any of them
}