rule TTP_XOR_WriteProcessMemory_d42e {
  strings:
    $key_d42e = { 83 5c [2] b1 7e [2] b7 4b [2] 99 4b [2] a6 57 }

  condition:
    any of them
}