rule TTP_XOR_WriteProcessMemory_e599 {
  strings:
    $key_e599 = { b2 eb [2] 80 c9 [2] 86 fc [2] a8 fc [2] 97 e0 }

  condition:
    any of them
}