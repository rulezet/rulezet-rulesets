rule TTP_XOR_WriteProcessMemory_f64e {
  strings:
    $key_f64e = { a1 3c [2] 93 1e [2] 95 2b [2] bb 2b [2] 84 37 }

  condition:
    any of them
}