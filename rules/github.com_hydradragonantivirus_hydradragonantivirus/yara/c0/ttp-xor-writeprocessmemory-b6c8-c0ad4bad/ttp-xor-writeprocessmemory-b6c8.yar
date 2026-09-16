rule TTP_XOR_WriteProcessMemory_b6c8 {
  strings:
    $key_b6c8 = { e1 ba [2] d3 98 [2] d5 ad [2] fb ad [2] c4 b1 }

  condition:
    any of them
}