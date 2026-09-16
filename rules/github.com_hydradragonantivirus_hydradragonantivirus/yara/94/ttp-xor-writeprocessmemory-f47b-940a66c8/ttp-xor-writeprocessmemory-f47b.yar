rule TTP_XOR_WriteProcessMemory_f47b {
  strings:
    $key_f47b = { a3 09 [2] 91 2b [2] 97 1e [2] b9 1e [2] 86 02 }

  condition:
    any of them
}