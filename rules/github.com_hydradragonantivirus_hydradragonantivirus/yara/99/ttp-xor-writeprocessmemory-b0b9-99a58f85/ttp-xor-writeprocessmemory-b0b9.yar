rule TTP_XOR_WriteProcessMemory_b0b9 {
  strings:
    $key_b0b9 = { e7 cb [2] d5 e9 [2] d3 dc [2] fd dc [2] c2 c0 }

  condition:
    any of them
}