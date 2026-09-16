rule TTP_XOR_WriteProcessMemory_f62a {
  strings:
    $key_f62a = { a1 58 [2] 93 7a [2] 95 4f [2] bb 4f [2] 84 53 }

  condition:
    any of them
}