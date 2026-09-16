rule TTP_XOR_WriteProcessMemory_2699 {
  strings:
    $key_2699 = { 71 eb [2] 43 c9 [2] 45 fc [2] 6b fc [2] 54 e0 }

  condition:
    any of them
}