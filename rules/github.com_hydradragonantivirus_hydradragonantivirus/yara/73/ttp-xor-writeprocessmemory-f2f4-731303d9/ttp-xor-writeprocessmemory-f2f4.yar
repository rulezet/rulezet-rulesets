rule TTP_XOR_WriteProcessMemory_f2f4 {
  strings:
    $key_f2f4 = { a5 86 [2] 97 a4 [2] 91 91 [2] bf 91 [2] 80 8d }

  condition:
    any of them
}