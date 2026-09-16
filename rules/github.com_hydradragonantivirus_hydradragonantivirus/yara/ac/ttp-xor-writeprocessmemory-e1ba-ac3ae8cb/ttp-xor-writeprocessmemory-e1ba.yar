rule TTP_XOR_WriteProcessMemory_e1ba {
  strings:
    $key_e1ba = { b6 c8 [2] 84 ea [2] 82 df [2] ac df [2] 93 c3 }

  condition:
    any of them
}