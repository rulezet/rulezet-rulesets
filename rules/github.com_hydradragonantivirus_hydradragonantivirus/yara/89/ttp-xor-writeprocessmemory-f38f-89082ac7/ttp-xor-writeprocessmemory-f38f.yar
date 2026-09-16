rule TTP_XOR_WriteProcessMemory_f38f {
  strings:
    $key_f38f = { a4 fd [2] 96 df [2] 90 ea [2] be ea [2] 81 f6 }

  condition:
    any of them
}