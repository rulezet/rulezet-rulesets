rule TTP_XOR_WriteProcessMemory_f72e {
  strings:
    $key_f72e = { a0 5c [2] 92 7e [2] 94 4b [2] ba 4b [2] 85 57 }

  condition:
    any of them
}