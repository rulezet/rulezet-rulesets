rule TTP_XOR_WriteProcessMemory_f26e {
  strings:
    $key_f26e = { a5 1c [2] 97 3e [2] 91 0b [2] bf 0b [2] 80 17 }

  condition:
    any of them
}