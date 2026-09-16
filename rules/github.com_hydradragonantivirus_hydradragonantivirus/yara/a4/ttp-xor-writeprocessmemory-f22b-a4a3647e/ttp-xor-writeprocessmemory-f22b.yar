rule TTP_XOR_WriteProcessMemory_f22b {
  strings:
    $key_f22b = { a5 59 [2] 97 7b [2] 91 4e [2] bf 4e [2] 80 52 }

  condition:
    any of them
}