rule TTP_XOR_WriteProcessMemory_f65d {
  strings:
    $key_f65d = { a1 2f [2] 93 0d [2] 95 38 [2] bb 38 [2] 84 24 }

  condition:
    any of them
}