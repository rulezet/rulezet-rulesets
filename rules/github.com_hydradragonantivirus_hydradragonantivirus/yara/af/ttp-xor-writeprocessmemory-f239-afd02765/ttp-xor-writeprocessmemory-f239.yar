rule TTP_XOR_WriteProcessMemory_f239 {
  strings:
    $key_f239 = { a5 4b [2] 97 69 [2] 91 5c [2] bf 5c [2] 80 40 }

  condition:
    any of them
}