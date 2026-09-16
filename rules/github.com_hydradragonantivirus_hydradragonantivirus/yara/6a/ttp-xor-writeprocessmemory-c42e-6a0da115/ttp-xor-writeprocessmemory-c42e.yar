rule TTP_XOR_WriteProcessMemory_c42e {
  strings:
    $key_c42e = { 93 5c [2] a1 7e [2] a7 4b [2] 89 4b [2] b6 57 }

  condition:
    any of them
}