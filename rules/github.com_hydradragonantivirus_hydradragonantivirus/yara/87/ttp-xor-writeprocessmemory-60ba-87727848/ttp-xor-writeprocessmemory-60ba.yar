rule TTP_XOR_WriteProcessMemory_60ba {
  strings:
    $key_60ba = { 37 c8 [2] 05 ea [2] 03 df [2] 2d df [2] 12 c3 }

  condition:
    any of them
}