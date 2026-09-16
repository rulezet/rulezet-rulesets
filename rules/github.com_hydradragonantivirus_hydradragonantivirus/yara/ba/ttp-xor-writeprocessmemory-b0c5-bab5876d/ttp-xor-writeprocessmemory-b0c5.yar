rule TTP_XOR_WriteProcessMemory_b0c5 {
  strings:
    $key_b0c5 = { e7 b7 [2] d5 95 [2] d3 a0 [2] fd a0 [2] c2 bc }

  condition:
    any of them
}