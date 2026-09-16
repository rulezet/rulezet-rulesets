rule TTP_XOR_WriteProcessMemory_f28f {
  strings:
    $key_f28f = { a5 fd [2] 97 df [2] 91 ea [2] bf ea [2] 80 f6 }

  condition:
    any of them
}