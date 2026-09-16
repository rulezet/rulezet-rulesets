rule TTP_XOR_WriteProcessMemory_f75b {
  strings:
    $key_f75b = { a0 29 [2] 92 0b [2] 94 3e [2] ba 3e [2] 85 22 }

  condition:
    any of them
}