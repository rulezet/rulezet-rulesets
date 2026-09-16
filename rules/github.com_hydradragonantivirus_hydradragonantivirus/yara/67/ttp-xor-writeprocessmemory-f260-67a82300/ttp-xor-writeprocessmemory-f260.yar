rule TTP_XOR_WriteProcessMemory_f260 {
  strings:
    $key_f260 = { a5 12 [2] 97 30 [2] 91 05 [2] bf 05 [2] 80 19 }

  condition:
    any of them
}