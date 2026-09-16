rule TTP_XOR_WriteProcessMemory_f2ec {
  strings:
    $key_f2ec = { a5 9e [2] 97 bc [2] 91 89 [2] bf 89 [2] 80 95 }

  condition:
    any of them
}