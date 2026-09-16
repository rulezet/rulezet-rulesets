rule TTP_XOR_WriteProcessMemory_f72b {
  strings:
    $key_f72b = { a0 59 [2] 92 7b [2] 94 4e [2] ba 4e [2] 85 52 }

  condition:
    any of them
}