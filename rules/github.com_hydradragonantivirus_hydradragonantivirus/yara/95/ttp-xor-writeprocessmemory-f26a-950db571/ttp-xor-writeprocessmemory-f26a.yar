rule TTP_XOR_WriteProcessMemory_f26a {
  strings:
    $key_f26a = { a5 18 [2] 97 3a [2] 91 0f [2] bf 0f [2] 80 13 }

  condition:
    any of them
}