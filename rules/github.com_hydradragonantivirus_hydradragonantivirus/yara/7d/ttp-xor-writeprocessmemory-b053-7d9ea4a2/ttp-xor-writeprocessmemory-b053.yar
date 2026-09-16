rule TTP_XOR_WriteProcessMemory_b053 {
  strings:
    $key_b053 = { e7 21 [2] d5 03 [2] d3 36 [2] fd 36 [2] c2 2a }

  condition:
    any of them
}