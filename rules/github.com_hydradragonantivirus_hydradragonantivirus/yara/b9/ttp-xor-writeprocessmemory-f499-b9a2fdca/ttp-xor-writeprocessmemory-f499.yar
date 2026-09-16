rule TTP_XOR_WriteProcessMemory_f499 {
  strings:
    $key_f499 = { a3 eb [2] 91 c9 [2] 97 fc [2] b9 fc [2] 86 e0 }

  condition:
    any of them
}