rule TTP_XOR_WriteProcessMemory_f240 {
  strings:
    $key_f240 = { a5 32 [2] 97 10 [2] 91 25 [2] bf 25 [2] 80 39 }

  condition:
    any of them
}