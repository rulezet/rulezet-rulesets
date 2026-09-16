rule TTP_XOR_WriteProcessMemory_b3b6 {
  strings:
    $key_b3b6 = { e4 c4 [2] d6 e6 [2] d0 d3 [2] fe d3 [2] c1 cf }

  condition:
    any of them
}