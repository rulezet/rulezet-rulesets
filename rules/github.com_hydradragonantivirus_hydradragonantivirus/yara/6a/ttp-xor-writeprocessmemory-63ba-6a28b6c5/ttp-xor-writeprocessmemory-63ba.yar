rule TTP_XOR_WriteProcessMemory_63ba {
  strings:
    $key_63ba = { 34 c8 [2] 06 ea [2] 00 df [2] 2e df [2] 11 c3 }

  condition:
    any of them
}