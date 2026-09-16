rule TTP_XOR_WriteProcessMemory_23ba {
  strings:
    $key_23ba = { 74 c8 [2] 46 ea [2] 40 df [2] 6e df [2] 51 c3 }

  condition:
    any of them
}