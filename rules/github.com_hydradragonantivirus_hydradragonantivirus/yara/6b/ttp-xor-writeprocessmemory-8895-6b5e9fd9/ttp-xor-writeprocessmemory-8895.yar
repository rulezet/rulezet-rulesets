rule TTP_XOR_WriteProcessMemory_8895 {
  strings:
    $key_8895 = { df e7 [2] ed c5 [2] eb f0 [2] c5 f0 [2] fa ec }

  condition:
    any of them
}