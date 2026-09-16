rule TTP_XOR_WriteProcessMemory_b4ba {
  strings:
    $key_b4ba = { e3 c8 [2] d1 ea [2] d7 df [2] f9 df [2] c6 c3 }

  condition:
    any of them
}