rule TTP_XOR_WriteProcessMemory_c78f {
  strings:
    $key_c78f = { 90 fd [2] a2 df [2] a4 ea [2] 8a ea [2] b5 f6 }

  condition:
    any of them
}