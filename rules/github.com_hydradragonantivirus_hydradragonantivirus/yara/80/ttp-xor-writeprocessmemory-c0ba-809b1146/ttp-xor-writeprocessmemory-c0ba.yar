rule TTP_XOR_WriteProcessMemory_c0ba {
  strings:
    $key_c0ba = { 97 c8 [2] a5 ea [2] a3 df [2] 8d df [2] b2 c3 }

  condition:
    any of them
}