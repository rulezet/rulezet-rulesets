rule TTP_XOR_WriteProcessMemory_f206 {
  strings:
    $key_f206 = { a5 74 [2] 97 56 [2] 91 63 [2] bf 63 [2] 80 7f }

  condition:
    any of them
}