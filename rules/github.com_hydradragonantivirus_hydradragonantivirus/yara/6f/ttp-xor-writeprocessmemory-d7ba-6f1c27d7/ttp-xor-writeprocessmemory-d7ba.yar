rule TTP_XOR_WriteProcessMemory_d7ba {
  strings:
    $key_d7ba = { 80 c8 [2] b2 ea [2] b4 df [2] 9a df [2] a5 c3 }

  condition:
    any of them
}