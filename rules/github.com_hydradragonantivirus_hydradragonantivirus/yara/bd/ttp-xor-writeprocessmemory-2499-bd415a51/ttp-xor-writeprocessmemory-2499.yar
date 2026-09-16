rule TTP_XOR_WriteProcessMemory_2499 {
  strings:
    $key_2499 = { 73 eb [2] 41 c9 [2] 47 fc [2] 69 fc [2] 56 e0 }

  condition:
    any of them
}