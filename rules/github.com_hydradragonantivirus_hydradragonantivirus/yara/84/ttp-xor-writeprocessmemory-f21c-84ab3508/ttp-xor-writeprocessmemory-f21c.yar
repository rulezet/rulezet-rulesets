rule TTP_XOR_WriteProcessMemory_f21c {
  strings:
    $key_f21c = { a5 6e [2] 97 4c [2] 91 79 [2] bf 79 [2] 80 65 }

  condition:
    any of them
}