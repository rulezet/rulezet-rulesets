rule TTP_XOR_WriteProcessMemory_74ba {
  strings:
    $key_74ba = { 23 c8 [2] 11 ea [2] 17 df [2] 39 df [2] 06 c3 }

  condition:
    any of them
}