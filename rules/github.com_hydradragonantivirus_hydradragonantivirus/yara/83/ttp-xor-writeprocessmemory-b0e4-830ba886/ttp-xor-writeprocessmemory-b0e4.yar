rule TTP_XOR_WriteProcessMemory_b0e4 {
  strings:
    $key_b0e4 = { e7 96 [2] d5 b4 [2] d3 81 [2] fd 81 [2] c2 9d }

  condition:
    any of them
}