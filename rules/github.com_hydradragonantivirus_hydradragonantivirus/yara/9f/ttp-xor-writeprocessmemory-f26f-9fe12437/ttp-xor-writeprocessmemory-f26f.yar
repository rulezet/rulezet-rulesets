rule TTP_XOR_WriteProcessMemory_f26f {
  strings:
    $key_f26f = { a5 1d [2] 97 3f [2] 91 0a [2] bf 0a [2] 80 16 }

  condition:
    any of them
}