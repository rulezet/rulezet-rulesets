rule TTP_XOR_WriteProcessMemory_f21b {
  strings:
    $key_f21b = { a5 69 [2] 97 4b [2] 91 7e [2] bf 7e [2] 80 62 }

  condition:
    any of them
}