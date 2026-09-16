rule TTP_XOR_WriteProcessMemory_f275 {
  strings:
    $key_f275 = { a5 07 [2] 97 25 [2] 91 10 [2] bf 10 [2] 80 0c }

  condition:
    any of them
}