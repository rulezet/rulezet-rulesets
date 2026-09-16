rule TTP_XOR_WriteProcessMemory_b022 {
  strings:
    $key_b022 = { e7 50 [2] d5 72 [2] d3 47 [2] fd 47 [2] c2 5b }

  condition:
    any of them
}