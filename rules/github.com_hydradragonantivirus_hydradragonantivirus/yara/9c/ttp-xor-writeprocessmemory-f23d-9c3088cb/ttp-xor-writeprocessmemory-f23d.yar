rule TTP_XOR_WriteProcessMemory_f23d {
  strings:
    $key_f23d = { a5 4f [2] 97 6d [2] 91 58 [2] bf 58 [2] 80 44 }

  condition:
    any of them
}