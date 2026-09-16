rule TTP_XOR_WriteProcessMemory_0ee5 {
  strings:
    $key_0ee5 = { 59 97 [2] 6b b5 [2] 6d 80 [2] 43 80 [2] 7c 9c }

  condition:
    any of them
}