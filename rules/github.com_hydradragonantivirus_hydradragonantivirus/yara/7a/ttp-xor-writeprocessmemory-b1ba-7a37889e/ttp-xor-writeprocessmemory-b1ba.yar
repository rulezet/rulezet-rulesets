rule TTP_XOR_WriteProcessMemory_b1ba {
  strings:
    $key_b1ba = { e6 c8 [2] d4 ea [2] d2 df [2] fc df [2] c3 c3 }

  condition:
    any of them
}