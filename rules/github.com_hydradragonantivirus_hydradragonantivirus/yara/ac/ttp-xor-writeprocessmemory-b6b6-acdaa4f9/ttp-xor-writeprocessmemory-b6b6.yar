rule TTP_XOR_WriteProcessMemory_b6b6 {
  strings:
    $key_b6b6 = { e1 c4 [2] d3 e6 [2] d5 d3 [2] fb d3 [2] c4 cf }

  condition:
    any of them
}