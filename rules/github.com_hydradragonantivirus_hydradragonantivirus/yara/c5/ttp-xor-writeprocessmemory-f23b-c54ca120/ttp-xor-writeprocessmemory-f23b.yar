rule TTP_XOR_WriteProcessMemory_f23b {
  strings:
    $key_f23b = { a5 49 [2] 97 6b [2] 91 5e [2] bf 5e [2] 80 42 }

  condition:
    any of them
}