rule TTP_XOR_WriteProcessMemory_43ba {
  strings:
    $key_43ba = { 14 c8 [2] 26 ea [2] 20 df [2] 0e df [2] 31 c3 }

  condition:
    any of them
}