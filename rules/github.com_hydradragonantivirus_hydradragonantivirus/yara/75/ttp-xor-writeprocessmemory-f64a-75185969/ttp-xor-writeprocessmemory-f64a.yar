rule TTP_XOR_WriteProcessMemory_f64a {
  strings:
    $key_f64a = { a1 38 [2] 93 1a [2] 95 2f [2] bb 2f [2] 84 33 }

  condition:
    any of them
}