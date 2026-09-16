rule TTP_XOR_WriteProcessMemory_b76f {
  strings:
    $key_b76f = { e0 1d [2] d2 3f [2] d4 0a [2] fa 0a [2] c5 16 }

  condition:
    any of them
}