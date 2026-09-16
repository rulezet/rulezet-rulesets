rule TTP_XOR_WriteProcessMemory_10ba {
  strings:
    $key_10ba = { 47 c8 [2] 75 ea [2] 73 df [2] 5d df [2] 62 c3 }

  condition:
    any of them
}