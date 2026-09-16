rule TTP_XOR_WriteProcessMemory_c58f {
  strings:
    $key_c58f = { 92 fd [2] a0 df [2] a6 ea [2] 88 ea [2] b7 f6 }

  condition:
    any of them
}