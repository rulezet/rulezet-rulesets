rule TTP_XOR_WriteProcessMemory_b012 {
  strings:
    $key_b012 = { e7 60 [2] d5 42 [2] d3 77 [2] fd 77 [2] c2 6b }

  condition:
    any of them
}