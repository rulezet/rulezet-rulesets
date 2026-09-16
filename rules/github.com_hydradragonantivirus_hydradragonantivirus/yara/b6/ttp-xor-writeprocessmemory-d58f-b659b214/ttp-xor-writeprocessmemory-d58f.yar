rule TTP_XOR_WriteProcessMemory_d58f {
  strings:
    $key_d58f = { 82 fd [2] b0 df [2] b6 ea [2] 98 ea [2] a7 f6 }

  condition:
    any of them
}