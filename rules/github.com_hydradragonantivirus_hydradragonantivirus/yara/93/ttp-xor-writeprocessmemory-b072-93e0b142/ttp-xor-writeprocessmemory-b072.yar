rule TTP_XOR_WriteProcessMemory_b072 {
  strings:
    $key_b072 = { e7 00 [2] d5 22 [2] d3 17 [2] fd 17 [2] c2 0b }

  condition:
    any of them
}