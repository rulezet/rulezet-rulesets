rule TTP_XOR_WriteProcessMemory_608f {
  strings:
    $key_608f = { 37 fd [2] 05 df [2] 03 ea [2] 2d ea [2] 12 f6 }

  condition:
    any of them
}