rule TTP_XOR_WriteProcessMemory_f20c {
  strings:
    $key_f20c = { a5 7e [2] 97 5c [2] 91 69 [2] bf 69 [2] 80 75 }

  condition:
    any of them
}