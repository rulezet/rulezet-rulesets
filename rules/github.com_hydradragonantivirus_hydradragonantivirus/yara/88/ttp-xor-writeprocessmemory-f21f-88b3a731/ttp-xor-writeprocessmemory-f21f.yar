rule TTP_XOR_WriteProcessMemory_f21f {
  strings:
    $key_f21f = { a5 6d [2] 97 4f [2] 91 7a [2] bf 7a [2] 80 66 }

  condition:
    any of them
}