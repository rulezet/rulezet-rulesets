rule TTP_XOR_WriteProcessMemory_1499 {
  strings:
    $key_1499 = { 43 eb [2] 71 c9 [2] 77 fc [2] 59 fc [2] 66 e0 }

  condition:
    any of them
}