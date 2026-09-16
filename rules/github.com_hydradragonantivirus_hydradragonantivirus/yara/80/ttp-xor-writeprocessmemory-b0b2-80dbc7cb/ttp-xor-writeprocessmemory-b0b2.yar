rule TTP_XOR_WriteProcessMemory_b0b2 {
  strings:
    $key_b0b2 = { e7 c0 [2] d5 e2 [2] d3 d7 [2] fd d7 [2] c2 cb }

  condition:
    any of them
}