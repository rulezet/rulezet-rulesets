rule TTP_XOR_WriteProcessMemory_f64d {
  strings:
    $key_f64d = { a1 3f [2] 93 1d [2] 95 28 [2] bb 28 [2] 84 34 }

  condition:
    any of them
}