rule TTP_XOR_WriteProcessMemory_f5ba {
  strings:
    $key_f5ba = { a2 c8 [2] 90 ea [2] 96 df [2] b8 df [2] 87 c3 }

  condition:
    any of them
}