rule TTP_XOR_WriteProcessMemory_3fe5 {
  strings:
    $key_3fe5 = { 68 97 [2] 5a b5 [2] 5c 80 [2] 72 80 [2] 4d 9c }

  condition:
    any of them
}