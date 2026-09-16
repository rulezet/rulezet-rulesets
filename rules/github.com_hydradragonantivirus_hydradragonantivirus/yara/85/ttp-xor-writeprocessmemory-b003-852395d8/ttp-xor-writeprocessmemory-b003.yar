rule TTP_XOR_WriteProcessMemory_b003 {
  strings:
    $key_b003 = { e7 71 [2] d5 53 [2] d3 66 [2] fd 66 [2] c2 7a }

  condition:
    any of them
}