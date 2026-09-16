rule TTP_XOR_WriteProcessMemory_f66a {
  strings:
    $key_f66a = { a1 18 [2] 93 3a [2] 95 0f [2] bb 0f [2] 84 13 }

  condition:
    any of them
}