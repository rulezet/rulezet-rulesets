rule TTP_XOR_WriteProcessMemory_f70e {
  strings:
    $key_f70e = { a0 7c [2] 92 5e [2] 94 6b [2] ba 6b [2] 85 77 }

  condition:
    any of them
}