rule TTP_XOR_WriteProcessMemory_d2ba {
  strings:
    $key_d2ba = { 85 c8 [2] b7 ea [2] b1 df [2] 9f df [2] a0 c3 }

  condition:
    any of them
}