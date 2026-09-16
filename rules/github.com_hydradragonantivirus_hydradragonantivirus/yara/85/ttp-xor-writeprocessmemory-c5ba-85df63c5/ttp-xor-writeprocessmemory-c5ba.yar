rule TTP_XOR_WriteProcessMemory_c5ba {
  strings:
    $key_c5ba = { 92 c8 [2] a0 ea [2] a6 df [2] 88 df [2] b7 c3 }

  condition:
    any of them
}