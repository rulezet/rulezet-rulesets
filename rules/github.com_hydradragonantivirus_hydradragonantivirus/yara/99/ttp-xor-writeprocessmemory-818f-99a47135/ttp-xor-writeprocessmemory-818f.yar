rule TTP_XOR_WriteProcessMemory_818f {
  strings:
    $key_818f = { d6 fd [2] e4 df [2] e2 ea [2] cc ea [2] f3 f6 }

  condition:
    any of them
}