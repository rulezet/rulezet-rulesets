rule TTP_XOR_WriteProcessMemory_12ba {
  strings:
    $key_12ba = { 45 c8 [2] 77 ea [2] 71 df [2] 5f df [2] 60 c3 }

  condition:
    any of them
}