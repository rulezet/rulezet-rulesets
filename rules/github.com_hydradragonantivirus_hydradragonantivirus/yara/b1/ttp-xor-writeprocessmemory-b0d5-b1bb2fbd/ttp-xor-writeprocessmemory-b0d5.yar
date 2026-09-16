rule TTP_XOR_WriteProcessMemory_b0d5 {
  strings:
    $key_b0d5 = { e7 a7 [2] d5 85 [2] d3 b0 [2] fd b0 [2] c2 ac }

  condition:
    any of them
}