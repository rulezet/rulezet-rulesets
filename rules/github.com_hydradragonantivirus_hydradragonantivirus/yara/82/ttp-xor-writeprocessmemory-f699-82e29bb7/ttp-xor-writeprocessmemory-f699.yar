rule TTP_XOR_WriteProcessMemory_f699 {
  strings:
    $key_f699 = { a1 eb [2] 93 c9 [2] 95 fc [2] bb fc [2] 84 e0 }

  condition:
    any of them
}