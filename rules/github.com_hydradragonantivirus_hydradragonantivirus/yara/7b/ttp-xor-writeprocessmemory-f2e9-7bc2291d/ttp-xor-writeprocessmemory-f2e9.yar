rule TTP_XOR_WriteProcessMemory_f2e9 {
  strings:
    $key_f2e9 = { a5 9b [2] 97 b9 [2] 91 8c [2] bf 8c [2] 80 90 }

  condition:
    any of them
}