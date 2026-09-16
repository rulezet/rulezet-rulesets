rule TTP_XOR_WriteProcessMemory_b016 {
  strings:
    $key_b016 = { e7 64 [2] d5 46 [2] d3 73 [2] fd 73 [2] c2 6f }

  condition:
    any of them
}