rule TTP_XOR_WriteProcessMemory_f23c {
  strings:
    $key_f23c = { a5 4e [2] 97 6c [2] 91 59 [2] bf 59 [2] 80 45 }

  condition:
    any of them
}