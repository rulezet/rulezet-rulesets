rule TTP_XOR_WriteProcessMemory_e28f {
  strings:
    $key_e28f = { b5 fd [2] 87 df [2] 81 ea [2] af ea [2] 90 f6 }

  condition:
    any of them
}