rule TTP_XOR_WriteProcessMemory_b0e5 {
  strings:
    $key_b0e5 = { e7 97 [2] d5 b5 [2] d3 80 [2] fd 80 [2] c2 9c }

  condition:
    any of them
}