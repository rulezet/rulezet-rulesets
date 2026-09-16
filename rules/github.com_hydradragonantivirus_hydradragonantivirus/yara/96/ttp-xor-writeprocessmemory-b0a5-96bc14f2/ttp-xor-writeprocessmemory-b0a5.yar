rule TTP_XOR_WriteProcessMemory_b0a5 {
  strings:
    $key_b0a5 = { e7 d7 [2] d5 f5 [2] d3 c0 [2] fd c0 [2] c2 dc }

  condition:
    any of them
}