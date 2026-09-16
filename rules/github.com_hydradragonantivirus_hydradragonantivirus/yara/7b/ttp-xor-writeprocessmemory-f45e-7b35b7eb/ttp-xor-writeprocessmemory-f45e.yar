rule TTP_XOR_WriteProcessMemory_f45e {
  strings:
    $key_f45e = { a3 2c [2] 91 0e [2] 97 3b [2] b9 3b [2] 86 27 }

  condition:
    any of them
}