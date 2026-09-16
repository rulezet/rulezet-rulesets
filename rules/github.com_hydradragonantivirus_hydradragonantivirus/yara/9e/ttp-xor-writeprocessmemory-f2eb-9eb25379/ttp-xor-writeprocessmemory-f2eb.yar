rule TTP_XOR_WriteProcessMemory_f2eb {
  strings:
    $key_f2eb = { a5 99 [2] 97 bb [2] 91 8e [2] bf 8e [2] 80 92 }

  condition:
    any of them
}