rule TTP_XOR_WriteProcessMemory_f3ba {
  strings:
    $key_f3ba = { a4 c8 [2] 96 ea [2] 90 df [2] be df [2] 81 c3 }

  condition:
    any of them
}