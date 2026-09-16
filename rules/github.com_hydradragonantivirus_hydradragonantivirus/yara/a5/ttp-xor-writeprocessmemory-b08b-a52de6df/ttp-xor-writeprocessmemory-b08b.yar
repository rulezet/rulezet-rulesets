rule TTP_XOR_WriteProcessMemory_b08b {
  strings:
    $key_b08b = { e7 f9 [2] d5 db [2] d3 ee [2] fd ee [2] c2 f2 }

  condition:
    any of them
}