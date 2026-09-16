rule TTP_XOR_WriteProcessMemory_15ba {
  strings:
    $key_15ba = { 42 c8 [2] 70 ea [2] 76 df [2] 58 df [2] 67 c3 }

  condition:
    any of them
}