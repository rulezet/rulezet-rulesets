rule TTP_XOR_WriteProcessMemory_f2f9 {
  strings:
    $key_f2f9 = { a5 8b [2] 97 a9 [2] 91 9c [2] bf 9c [2] 80 80 }

  condition:
    any of them
}