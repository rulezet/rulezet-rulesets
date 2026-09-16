rule TTP_XOR_WriteProcessMemory_148f {
  strings:
    $key_148f = { 43 fd [2] 71 df [2] 77 ea [2] 59 ea [2] 66 f6 }

  condition:
    any of them
}