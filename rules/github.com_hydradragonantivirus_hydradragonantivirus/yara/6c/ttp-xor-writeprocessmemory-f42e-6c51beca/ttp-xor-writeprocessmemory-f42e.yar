rule TTP_XOR_WriteProcessMemory_f42e {
  strings:
    $key_f42e = { a3 5c [2] 91 7e [2] 97 4b [2] b9 4b [2] 86 57 }

  condition:
    any of them
}