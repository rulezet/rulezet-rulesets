rule TTP_XOR_WriteProcessMemory_b0a7 {
  strings:
    $key_b0a7 = { e7 d5 [2] d5 f7 [2] d3 c2 [2] fd c2 [2] c2 de }

  condition:
    any of them
}