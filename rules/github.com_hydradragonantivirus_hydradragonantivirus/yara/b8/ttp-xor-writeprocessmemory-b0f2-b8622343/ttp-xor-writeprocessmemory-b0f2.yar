rule TTP_XOR_WriteProcessMemory_b0f2 {
  strings:
    $key_b0f2 = { e7 80 [2] d5 a2 [2] d3 97 [2] fd 97 [2] c2 8b }

  condition:
    any of them
}