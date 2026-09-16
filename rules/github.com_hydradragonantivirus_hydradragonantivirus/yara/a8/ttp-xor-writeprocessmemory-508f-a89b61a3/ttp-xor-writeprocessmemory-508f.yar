rule TTP_XOR_WriteProcessMemory_508f {
  strings:
    $key_508f = { 07 fd [2] 35 df [2] 33 ea [2] 1d ea [2] 22 f6 }

  condition:
    any of them
}