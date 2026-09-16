rule TTP_XOR_WriteProcessMemory_f65f {
  strings:
    $key_f65f = { a1 2d [2] 93 0f [2] 95 3a [2] bb 3a [2] 84 26 }

  condition:
    any of them
}