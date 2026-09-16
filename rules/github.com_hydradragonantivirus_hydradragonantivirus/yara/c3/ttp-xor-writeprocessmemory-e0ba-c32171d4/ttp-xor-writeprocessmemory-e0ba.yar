rule TTP_XOR_WriteProcessMemory_e0ba {
  strings:
    $key_e0ba = { b7 c8 [2] 85 ea [2] 83 df [2] ad df [2] 92 c3 }

  condition:
    any of them
}