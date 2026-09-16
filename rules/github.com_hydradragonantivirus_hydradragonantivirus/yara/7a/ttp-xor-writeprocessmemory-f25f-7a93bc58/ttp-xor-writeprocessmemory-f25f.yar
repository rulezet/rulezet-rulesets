rule TTP_XOR_WriteProcessMemory_f25f {
  strings:
    $key_f25f = { a5 2d [2] 97 0f [2] 91 3a [2] bf 3a [2] 80 26 }

  condition:
    any of them
}