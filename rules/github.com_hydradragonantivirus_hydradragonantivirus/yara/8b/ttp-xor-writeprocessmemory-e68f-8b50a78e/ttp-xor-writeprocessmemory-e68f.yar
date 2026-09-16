rule TTP_XOR_WriteProcessMemory_e68f {
  strings:
    $key_e68f = { b1 fd [2] 83 df [2] 85 ea [2] ab ea [2] 94 f6 }

  condition:
    any of them
}