rule TTP_XOR_WriteProcessMemory_f67f {
  strings:
    $key_f67f = { a1 0d [2] 93 2f [2] 95 1a [2] bb 1a [2] 84 06 }

  condition:
    any of them
}