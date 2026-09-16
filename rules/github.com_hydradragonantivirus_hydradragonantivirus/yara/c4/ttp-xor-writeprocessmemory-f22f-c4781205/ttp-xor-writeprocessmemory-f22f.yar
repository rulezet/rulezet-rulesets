rule TTP_XOR_WriteProcessMemory_f22f {
  strings:
    $key_f22f = { a5 5d [2] 97 7f [2] 91 4a [2] bf 4a [2] 80 56 }

  condition:
    any of them
}