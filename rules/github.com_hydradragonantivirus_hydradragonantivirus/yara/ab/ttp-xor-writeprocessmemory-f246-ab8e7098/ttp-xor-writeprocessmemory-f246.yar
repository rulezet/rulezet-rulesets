rule TTP_XOR_WriteProcessMemory_f246 {
  strings:
    $key_f246 = { a5 34 [2] 97 16 [2] 91 23 [2] bf 23 [2] 80 3f }

  condition:
    any of them
}