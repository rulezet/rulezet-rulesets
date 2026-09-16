rule TTP_XOR_WriteProcessMemory_f243 {
  strings:
    $key_f243 = { a5 31 [2] 97 13 [2] 91 26 [2] bf 26 [2] 80 3a }

  condition:
    any of them
}