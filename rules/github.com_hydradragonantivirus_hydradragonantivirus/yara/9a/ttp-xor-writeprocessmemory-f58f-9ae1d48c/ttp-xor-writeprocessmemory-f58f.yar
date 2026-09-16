rule TTP_XOR_WriteProcessMemory_f58f {
  strings:
    $key_f58f = { a2 fd [2] 90 df [2] 96 ea [2] b8 ea [2] 87 f6 }

  condition:
    any of them
}