rule TTP_XOR_WriteProcessMemory_c9ba {
  strings:
    $key_c9ba = { 9e c8 [2] ac ea [2] aa df [2] 84 df [2] bb c3 }

  condition:
    any of them
}