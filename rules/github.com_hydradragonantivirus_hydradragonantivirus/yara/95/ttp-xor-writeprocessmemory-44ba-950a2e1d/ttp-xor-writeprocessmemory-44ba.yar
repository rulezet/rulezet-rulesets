rule TTP_XOR_WriteProcessMemory_44ba {
  strings:
    $key_44ba = { 13 c8 [2] 21 ea [2] 27 df [2] 09 df [2] 36 c3 }

  condition:
    any of them
}