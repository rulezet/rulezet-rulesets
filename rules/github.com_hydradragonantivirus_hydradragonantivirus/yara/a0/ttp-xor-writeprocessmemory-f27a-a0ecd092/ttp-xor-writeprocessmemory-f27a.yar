rule TTP_XOR_WriteProcessMemory_f27a {
  strings:
    $key_f27a = { a5 08 [2] 97 2a [2] 91 1f [2] bf 1f [2] 80 03 }

  condition:
    any of them
}