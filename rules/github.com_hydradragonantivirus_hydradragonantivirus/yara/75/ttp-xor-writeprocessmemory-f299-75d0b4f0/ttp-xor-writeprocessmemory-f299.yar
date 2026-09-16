rule TTP_XOR_WriteProcessMemory_f299 {
  strings:
    $key_f299 = { a5 eb [2] 97 c9 [2] 91 fc [2] bf fc [2] 80 e0 }

  condition:
    any of them
}