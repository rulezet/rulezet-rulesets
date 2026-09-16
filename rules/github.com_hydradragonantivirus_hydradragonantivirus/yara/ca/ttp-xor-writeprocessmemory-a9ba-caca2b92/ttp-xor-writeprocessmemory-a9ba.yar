rule TTP_XOR_WriteProcessMemory_a9ba {
  strings:
    $key_a9ba = { fe c8 [2] cc ea [2] ca df [2] e4 df [2] db c3 }

  condition:
    any of them
}