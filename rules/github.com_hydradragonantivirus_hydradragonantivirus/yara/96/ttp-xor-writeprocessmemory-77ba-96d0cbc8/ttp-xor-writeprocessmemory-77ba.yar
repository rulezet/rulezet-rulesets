rule TTP_XOR_WriteProcessMemory_77ba {
  strings:
    $key_77ba = { 20 c8 [2] 12 ea [2] 14 df [2] 3a df [2] 05 c3 }

  condition:
    any of them
}