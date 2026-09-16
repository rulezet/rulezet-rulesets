rule TTP_XOR_WriteProcessMemory_f253 {
  strings:
    $key_f253 = { a5 21 [2] 97 03 [2] 91 36 [2] bf 36 [2] 80 2a }

  condition:
    any of them
}