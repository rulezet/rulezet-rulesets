rule TTP_XOR_WriteProcessMemory_b077 {
  strings:
    $key_b077 = { e7 05 [2] d5 27 [2] d3 12 [2] fd 12 [2] c2 0e }

  condition:
    any of them
}