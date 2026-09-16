rule TTP_XOR_WriteProcessMemory_f47f {
  strings:
    $key_f47f = { a3 0d [2] 91 2f [2] 97 1a [2] b9 1a [2] 86 06 }

  condition:
    any of them
}