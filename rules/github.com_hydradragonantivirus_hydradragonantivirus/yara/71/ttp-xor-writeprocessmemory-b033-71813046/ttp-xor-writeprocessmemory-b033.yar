rule TTP_XOR_WriteProcessMemory_b033 {
  strings:
    $key_b033 = { e7 41 [2] d5 63 [2] d3 56 [2] fd 56 [2] c2 4a }

  condition:
    any of them
}