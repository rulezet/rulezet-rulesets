rule TTP_XOR_WriteProcessMemory_e48f {
  strings:
    $key_e48f = { b3 fd [2] 81 df [2] 87 ea [2] a9 ea [2] 96 f6 }

  condition:
    any of them
}