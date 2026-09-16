rule TTP_XOR_WriteProcessMemory_b031 {
  strings:
    $key_b031 = { e7 43 [2] d5 61 [2] d3 54 [2] fd 54 [2] c2 48 }

  condition:
    any of them
}