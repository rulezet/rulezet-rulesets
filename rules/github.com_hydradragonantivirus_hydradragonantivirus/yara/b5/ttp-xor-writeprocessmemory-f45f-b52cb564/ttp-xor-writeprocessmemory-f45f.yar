rule TTP_XOR_WriteProcessMemory_f45f {
  strings:
    $key_f45f = { a3 2d [2] 91 0f [2] 97 3a [2] b9 3a [2] 86 26 }

  condition:
    any of them
}