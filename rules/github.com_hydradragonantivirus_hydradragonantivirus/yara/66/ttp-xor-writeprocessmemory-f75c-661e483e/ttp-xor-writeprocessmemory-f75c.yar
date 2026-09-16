rule TTP_XOR_WriteProcessMemory_f75c {
  strings:
    $key_f75c = { a0 2e [2] 92 0c [2] 94 39 [2] ba 39 [2] 85 25 }

  condition:
    any of them
}