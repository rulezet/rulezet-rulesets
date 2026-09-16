rule TTP_XOR_WriteProcessMemory_f53e {
  strings:
    $key_f53e = { a2 4c [2] 90 6e [2] 96 5b [2] b8 5b [2] 87 47 }

  condition:
    any of them
}