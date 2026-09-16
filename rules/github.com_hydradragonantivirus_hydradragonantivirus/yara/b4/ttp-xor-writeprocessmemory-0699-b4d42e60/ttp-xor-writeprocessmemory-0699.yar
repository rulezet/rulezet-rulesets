rule TTP_XOR_WriteProcessMemory_0699 {
  strings:
    $key_0699 = { 51 eb [2] 63 c9 [2] 65 fc [2] 4b fc [2] 74 e0 }

  condition:
    any of them
}