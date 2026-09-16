rule TTP_XOR_WriteProcessMemory_b013 {
  strings:
    $key_b013 = { e7 61 [2] d5 43 [2] d3 76 [2] fd 76 [2] c2 6a }

  condition:
    any of them
}