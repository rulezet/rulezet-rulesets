rule TTP_XOR_WriteProcessMemory_f46e {
  strings:
    $key_f46e = { a3 1c [2] 91 3e [2] 97 0b [2] b9 0b [2] 86 17 }

  condition:
    any of them
}