rule TTP_XOR_WriteProcessMemory_f46b {
  strings:
    $key_f46b = { a3 19 [2] 91 3b [2] 97 0e [2] b9 0e [2] 86 12 }

  condition:
    any of them
}