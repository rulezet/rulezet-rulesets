rule TTP_XOR_WriteProcessMemory_9eba {
  strings:
    $key_9eba = { c9 c8 [2] fb ea [2] fd df [2] d3 df [2] ec c3 }

  condition:
    any of them
}