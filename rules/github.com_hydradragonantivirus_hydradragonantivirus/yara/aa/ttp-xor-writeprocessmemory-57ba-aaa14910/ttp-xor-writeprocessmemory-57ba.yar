rule TTP_XOR_WriteProcessMemory_57ba {
  strings:
    $key_57ba = { 00 c8 [2] 32 ea [2] 34 df [2] 1a df [2] 25 c3 }

  condition:
    any of them
}