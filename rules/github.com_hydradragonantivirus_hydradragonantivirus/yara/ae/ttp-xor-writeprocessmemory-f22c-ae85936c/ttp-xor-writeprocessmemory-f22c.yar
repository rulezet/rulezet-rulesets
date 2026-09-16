rule TTP_XOR_WriteProcessMemory_f22c {
  strings:
    $key_f22c = { a5 5e [2] 97 7c [2] 91 49 [2] bf 49 [2] 80 55 }

  condition:
    any of them
}