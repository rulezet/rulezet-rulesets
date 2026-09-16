rule TTP_XOR_WriteProcessMemory_d28f {
  strings:
    $key_d28f = { 85 fd [2] b7 df [2] b1 ea [2] 9f ea [2] a0 f6 }

  condition:
    any of them
}