rule TTP_XOR_WriteProcessMemory_f23f {
  strings:
    $key_f23f = { a5 4d [2] 97 6f [2] 91 5a [2] bf 5a [2] 80 46 }

  condition:
    any of them
}