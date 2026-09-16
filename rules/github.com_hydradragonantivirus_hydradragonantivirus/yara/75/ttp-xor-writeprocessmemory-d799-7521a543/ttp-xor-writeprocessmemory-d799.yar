rule TTP_XOR_WriteProcessMemory_d799 {
  strings:
    $key_d799 = { 80 eb [2] b2 c9 [2] b4 fc [2] 9a fc [2] a5 e0 }

  condition:
    any of them
}